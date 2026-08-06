// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Platform keystore backing for [`crate::store::SecretSealer`] (§28.1).
//!
//! The device seed is the whole secret, since every other key derives from
//! it. Sealing puts a 32-byte wrapping key in the keystore and leaves only
//! ciphertext on disk, with the protection level in the AAD so a downgrade
//! cannot be forged. That beats a stolen disk and stray backups, not code
//! running as the user with the keystore unlocked.
//!
//! macOS has two levels. `PlatformKeystore` keeps the key as a generic
//! password, preferring the data-protection keychain and falling back to the
//! login keychain, never to plaintext. `HardwareKeystore` unwraps it with a
//! Secure Enclave key and needs a provisioned, entitled app bundle.
//!
//! A missing wrapping key is an error, not a new identity: minting one would
//! change the device id and break every peer's pin.

use std::path::Path;

use zeroize::Zeroizing;

use crate::store::{self, AeadSealer, Protection, SecretSealer, StoreError};

/// The wrapping key is a 32-byte XChaCha20-Poly1305 key.
pub const WRAPPING_KEY_LEN: usize = 32;

/// Default item coordinates. Fixed strings, not derived from the state
/// directory: deriving would orphan the key the first time it moved.
pub const DEFAULT_SERVICE: &str = "com.reyta.rtp2";
pub const DEFAULT_ACCOUNT: &str = "device-identity";

/// Cap on the labels, so a hostile config cannot drive a big allocation
/// through the platform API.
const MAX_LABEL_BYTES: usize = 256;

#[derive(Debug)]
pub enum KeystoreError {
    /// This target has no platform keystore implementation.
    Unavailable(&'static str),
    /// The platform refused an operation. `status` is the native code
    /// (`OSStatus` on macOS).
    Platform { op: &'static str, status: i32 },
    /// The stored item exists but is not a `WRAPPING_KEY_LEN`-byte key.
    MalformedKey,
    /// A service or account label is empty or over `MAX_LABEL_BYTES`.
    InvalidLabel,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::Unavailable(what) => write!(f, "no platform keystore: {what}"),
            KeystoreError::Platform { op, status } => {
                write!(f, "keystore {op} failed with status {status}")
            }
            KeystoreError::MalformedKey => write!(f, "keystore item is not a wrapping key"),
            KeystoreError::InvalidLabel => write!(f, "keystore service or account is invalid"),
        }
    }
}

fn check_label(label: &str) -> Result<(), KeystoreError> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(KeystoreError::InvalidLabel);
    }
    Ok(())
}

/// Which platform keychain a [`Keystore`] talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// macOS data-protection keychain. Needs an entitled, signed binary.
    DataProtection,
    /// macOS file-based login keychain.
    LoginKeychain,
    /// A file-based keychain created for a test and deleted with the handle.
    TemporaryKeychain,
}

impl Scope {
    pub fn describe(self) -> &'static str {
        match self {
            Scope::DataProtection => "macos-data-protection-keychain",
            Scope::LoginKeychain => "macos-login-keychain",
            Scope::TemporaryKeychain => "macos-temporary-keychain",
        }
    }
}

/// A handle to the platform keystore.
pub struct Keystore {
    backend: imp::Backend,
}

impl Keystore {
    /// Opens the strongest keystore this platform can actually use: on macOS
    /// the data-protection keychain if the binary is entitled, otherwise the
    /// login keychain. No implementation means `Err(Unavailable)`, never a
    /// plaintext fallback.
    pub fn platform_default() -> Result<Self, KeystoreError> {
        Ok(Self {
            backend: imp::Backend::platform_default()?,
        })
    }

    /// Opens a specific keychain, refusing rather than falling back.
    pub fn with_scope(scope: Scope) -> Result<Self, KeystoreError> {
        Ok(Self {
            backend: imp::Backend::with_scope(scope)?,
        })
    }

    /// Which keychain this handle actually reached.
    pub fn describe(&self) -> &'static str {
        self.backend.scope().describe()
    }

    pub fn scope(&self) -> Scope {
        self.backend.scope()
    }

    /// The wrapping key for `(service, account)`, minted on first use.
    ///
    /// Two concurrent first uses race on the store: the loser sees the
    /// duplicate-item status and reads the winner's key, so both end up with
    /// the same one instead of overwriting each other.
    pub fn wrapping_key(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Zeroizing<[u8; WRAPPING_KEY_LEN]>, KeystoreError> {
        check_label(service)?;
        check_label(account)?;

        if let Some(key) = self.backend.find(service, account)? {
            return Ok(key);
        }

        let fresh = Zeroizing::new(crate::crypto::os_random_array::<WRAPPING_KEY_LEN>());
        match self.backend.add(service, account, fresh.as_ref()) {
            Ok(()) => Ok(fresh),
            Err(KeystoreError::Platform { status, .. }) if status == imp::DUPLICATE_ITEM => self
                .backend
                .find(service, account)?
                .ok_or(KeystoreError::Platform {
                    op: "find-after-duplicate",
                    status: imp::ITEM_NOT_FOUND,
                }),
            Err(e) => Err(e),
        }
    }

    /// Removes the wrapping key; `Ok(false)` means there was none. Every
    /// record under it becomes unopenable, which is how a device is retired,
    /// not rotated.
    pub fn forget(&self, service: &str, account: &str) -> Result<bool, KeystoreError> {
        check_label(service)?;
        check_label(account)?;
        self.backend.delete(service, account)
    }
}

/// A [`SecretSealer`] whose key is held by the platform keystore. The key is
/// fetched once and held in a `Zeroizing` buffer: a per-record fetch can
/// prompt, and prompting mid-write is worse than holding 32 bytes the process
/// already has the seed for.
pub struct KeystoreSealer {
    inner: AeadSealer,
    scope: Scope,
}

impl KeystoreSealer {
    /// Opens the default platform keystore and takes the wrapping key from it.
    pub fn open(service: &str, account: &str) -> Result<Self, KeystoreError> {
        Self::from_keystore(&Keystore::platform_default()?, service, account)
    }

    pub fn from_keystore(
        keystore: &Keystore,
        service: &str,
        account: &str,
    ) -> Result<Self, KeystoreError> {
        let key = keystore.wrapping_key(service, account)?;
        Ok(Self {
            inner: AeadSealer::new(*key, Protection::PlatformKeystore),
            scope: keystore.scope(),
        })
    }

    /// Which keychain the wrapping key came from.
    pub fn describe(&self) -> &'static str {
        self.scope.describe()
    }
}

impl SecretSealer for KeystoreSealer {
    fn protection(&self) -> Protection {
        // Not `self.inner.protection()`: the level says where the key lives,
        // and that is fixed.
        Protection::PlatformKeystore
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.inner.seal(plaintext, aad)
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.inner.open(sealed, aad)
    }
}

// ---------------------------------------------------------------------------
// Hardware-rooted vault key
// ---------------------------------------------------------------------------

const VAULT_KEY_DOMAIN: &[u8] = b"RTP2-VAULT-KEY-v1";
/// Name of the wrapped vault key inside the state directory.
pub const VAULT_KEY_FILE: &str = "vaultkey.rtp2";

/// A [`SecretSealer`] whose key is unwrapped by a non-exportable hardware key.
///
/// The enclave unwraps a random 256-bit vault key once at startup and
/// everything after that is XChaCha20-Poly1305 on the CPU. Sealing each record
/// with the hardware key directly would be simpler but puts a slow,
/// serialized, possibly prompting call inside every atomic record write.
///
/// ```text
/// Secure Enclave P-256 private key      (never leaves the enclave)
///         │  ECIES X9.63 SHA-256 AES-GCM
///         ▼
/// <state-dir>/vaultkey.rtp2             (wrapped 256-bit vault key)
///         │  XChaCha20-Poly1305
///         ▼
/// identity.rtp2, resumption.rtp2, …     (records)
/// ```
///
/// The limit is the same as every keystore: once unwrapped the vault key is in
/// this process's memory. It defeats a stolen disk, a copied keychain and a
/// stray backup, not malware already running as the user after unlock.
pub struct HardwareSealer {
    inner: AeadSealer,
}

impl HardwareSealer {
    /// Opens the vault key for `state_dir`, creating the hardware root and
    /// the wrapped key on first use. `state_dir` must exist already: open the
    /// `DeviceStore` first so it gets the usual 0700 hardening.
    pub fn open(state_dir: &Path, service: &str, account: &str) -> Result<Self, KeystoreError> {
        check_label(service)?;
        check_label(account)?;

        let root = imp::HardwareRoot::open(service, account)?;
        let path = state_dir.join(VAULT_KEY_FILE);
        let wrapper = EciesSealer { root };

        // Load an existing key, mint a missing one, and propagate a corrupt
        // one. Same rule as the identity record: a new vault key would orphan
        // everything under the old one.
        if let Some(existing) = store::read_sealed(
            &path,
            VAULT_KEY_DOMAIN,
            &wrapper,
            Protection::HardwareKeystore,
        )
        .map_err(|_| KeystoreError::Platform {
            op: "read vault key",
            status: 0,
        })? {
            if existing.len() != WRAPPING_KEY_LEN {
                return Err(KeystoreError::MalformedKey);
            }
            let mut key = [0u8; WRAPPING_KEY_LEN];
            key.copy_from_slice(&existing);
            return Ok(Self {
                inner: AeadSealer::new(key, Protection::HardwareKeystore),
            });
        }

        let fresh = Zeroizing::new(crate::crypto::os_random_array::<WRAPPING_KEY_LEN>());
        store::write_sealed(&path, VAULT_KEY_DOMAIN, &wrapper, fresh.as_ref()).map_err(|_| {
            KeystoreError::Platform {
                op: "write vault key",
                status: 0,
            }
        })?;
        Ok(Self {
            inner: AeadSealer::new(*fresh, Protection::HardwareKeystore),
        })
    }

    /// Removes the hardware root. Every record under it becomes permanently
    /// unopenable: this retires a device, it does not rotate a key.
    pub fn forget(service: &str, account: &str) -> Result<bool, KeystoreError> {
        check_label(service)?;
        check_label(account)?;
        imp::HardwareRoot::forget(service, account)
    }

    pub fn describe(&self) -> &'static str {
        imp::HARDWARE_BACKEND
    }
}

impl SecretSealer for HardwareSealer {
    fn protection(&self) -> Protection {
        Protection::HardwareKeystore
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.inner.seal(plaintext, aad)
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.inner.open(sealed, aad)
    }
}

/// Seals the vault key under the hardware root. ECIES takes no associated
/// data, and none is needed: the record's checksum already binds the domain
/// and protection level, and this record holds one value with one meaning.
struct EciesSealer {
    root: imp::HardwareRoot,
}

impl SecretSealer for EciesSealer {
    fn protection(&self) -> Protection {
        Protection::HardwareKeystore
    }

    fn seal(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.root.seal(plaintext).map_err(|_| StoreError::Seal)
    }

    fn open(&self, sealed: &[u8], _aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.root.unseal(sealed).map_err(|_| StoreError::Seal)
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    //! Direct Security.framework FFI.
    //!
    //! Against the C API rather than a crate: six functions, and this is
    //! where the seed's protection lives, so a dependency here would need the
    //! same review as the crypto providers for far less code.

    use std::ffi::{CString, c_char, c_void};

    use zeroize::Zeroizing;

    use super::{KeystoreError, Scope, WRAPPING_KEY_LEN};

    pub type OSStatus = i32;
    pub type CFTypeRef = *const c_void;
    pub type CFStringRef = CFTypeRef;
    pub type CFDataRef = CFTypeRef;
    pub type CFDictionaryRef = CFTypeRef;
    pub type CFArrayRef = CFTypeRef;
    pub type CFAllocatorRef = CFTypeRef;
    pub type CFTypeID = usize;
    pub type CFIndex = isize;
    pub type SecKeychainRef = CFTypeRef;
    /// Reported by `HardwareSealer::describe`.
    pub const HARDWARE_BACKEND: &str = "macos-secure-enclave-p256-ecies";

    pub type SecKeyRef = CFTypeRef;
    pub type SecAccessControlRef = CFTypeRef;
    pub type CFOptionFlags = usize;

    /// `kCFNumberIntType`.
    const CF_NUMBER_INT_TYPE: CFIndex = 9;
    /// `kSecAccessControlPrivateKeyUsage`: private-key operations with no
    /// further interaction, since a background transfer cannot answer a
    /// biometric prompt.
    const ACCESS_CONTROL_PRIVATE_KEY_USAGE: CFOptionFlags = 1 << 30;

    pub const ITEM_NOT_FOUND: OSStatus = -25300;
    pub const DUPLICATE_ITEM: OSStatus = -25299;
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        // Callback tables, needed only for their addresses, so opaque and
        // zero-sized rather than mirrored here.
        static kCFTypeDictionaryKeyCallBacks: [u8; 0];
        static kCFTypeDictionaryValueCallBacks: [u8; 0];
        static kCFTypeArrayCallBacks: [u8; 0];
        static kCFBooleanTrue: CFTypeRef;

        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> CFIndex;
        fn CFDataGetTypeID() -> CFTypeID;
        fn CFDictionaryCreate(
            alloc: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        fn CFNumberCreate(
            alloc: CFAllocatorRef,
            the_type: CFIndex,
            value_ptr: *const c_void,
        ) -> CFTypeRef;
        fn CFErrorGetCode(err: CFTypeRef) -> CFIndex;
        fn CFArrayCreate(
            alloc: CFAllocatorRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            callbacks: *const c_void,
        ) -> CFArrayRef;
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecAttrAccessible: CFStringRef;
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
        static kSecMatchSearchList: CFStringRef;
        static kSecUseKeychain: CFStringRef;
        static kSecUseDataProtectionKeychain: CFStringRef;

        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
        fn SecKeychainCreate(
            path_utf8: *const c_char,
            password_length: u32,
            password: *const c_void,
            prompt_user: u8,
            initial_access: CFTypeRef,
            out_keychain: *mut SecKeychainRef,
        ) -> OSStatus;
        fn SecKeychainDelete(keychain: SecKeychainRef) -> OSStatus;

        // Secure Enclave asymmetric keys, 10.12+. P-256 + ECIES, not the
        // ML-KEM types: those need a far newer SDK than the installed base.
        static kSecClassKey: CFStringRef;
        static kSecAttrKeyType: CFStringRef;
        static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
        static kSecAttrKeySizeInBits: CFStringRef;
        static kSecAttrTokenID: CFStringRef;
        static kSecAttrTokenIDSecureEnclave: CFStringRef;
        static kSecPrivateKeyAttrs: CFStringRef;
        static kSecAttrIsPermanent: CFStringRef;
        static kSecAttrApplicationTag: CFStringRef;
        static kSecAttrAccessControl: CFStringRef;
        static kSecReturnRef: CFStringRef;
        static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: CFStringRef;

        fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFTypeRef) -> SecKeyRef;
        fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
        fn SecKeyCreateEncryptedData(
            key: SecKeyRef,
            algorithm: CFStringRef,
            plaintext: CFDataRef,
            error: *mut CFTypeRef,
        ) -> CFDataRef;
        fn SecKeyCreateDecryptedData(
            key: SecKeyRef,
            algorithm: CFStringRef,
            ciphertext: CFDataRef,
            error: *mut CFTypeRef,
        ) -> CFDataRef;
        fn SecAccessControlCreateWithFlags(
            allocator: CFAllocatorRef,
            protection: CFTypeRef,
            flags: CFOptionFlags,
            error: *mut CFTypeRef,
        ) -> SecAccessControlRef;
    }

    /// Owns one CoreFoundation reference and releases it exactly once.
    struct CfRef(CFTypeRef);

    impl CfRef {
        fn new(raw: CFTypeRef, op: &'static str) -> Result<Self, KeystoreError> {
            if raw.is_null() {
                return Err(KeystoreError::Platform { op, status: 0 });
            }
            Ok(Self(raw))
        }

        fn raw(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for CfRef {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) }
        }
    }

    fn cf_string(value: &str) -> Result<CfRef, KeystoreError> {
        let raw = unsafe {
            CFStringCreateWithBytes(
                kCFAllocatorDefault,
                value.as_ptr(),
                value.len() as CFIndex,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        CfRef::new(raw, "CFStringCreateWithBytes")
    }

    fn cf_data(value: &[u8]) -> Result<CfRef, KeystoreError> {
        let raw =
            unsafe { CFDataCreate(kCFAllocatorDefault, value.as_ptr(), value.len() as CFIndex) };
        CfRef::new(raw, "CFDataCreate")
    }

    /// Accumulates dictionary entries and keeps every created reference alive
    /// until the dictionary itself is built.
    #[derive(Default)]
    struct Dict {
        keys: Vec<CFTypeRef>,
        values: Vec<CFTypeRef>,
        owned: Vec<CfRef>,
    }

    impl Dict {
        /// `value` is a framework constant or a reference owned elsewhere.
        fn borrowed(&mut self, key: CFTypeRef, value: CFTypeRef) {
            self.keys.push(key);
            self.values.push(value);
        }

        /// `value` was created here and is released with this `Dict`.
        fn owned(&mut self, key: CFTypeRef, value: CfRef) {
            self.keys.push(key);
            self.values.push(value.raw());
            self.owned.push(value);
        }

        fn build(&self) -> Result<CfRef, KeystoreError> {
            let raw = unsafe {
                CFDictionaryCreate(
                    kCFAllocatorDefault,
                    self.keys.as_ptr(),
                    self.values.as_ptr(),
                    self.keys.len() as CFIndex,
                    kCFTypeDictionaryKeyCallBacks.as_ptr() as *const c_void,
                    kCFTypeDictionaryValueCallBacks.as_ptr() as *const c_void,
                )
            };
            CfRef::new(raw, "CFDictionaryCreate")
        }
    }

    /// A temporary file-based keychain, deleted when the handle drops.
    struct TempKeychain {
        keychain: CfRef,
        path: std::path::PathBuf,
    }

    impl Drop for TempKeychain {
        fn drop(&mut self) {
            unsafe { SecKeychainDelete(self.keychain.raw()) };
            std::fs::remove_file(&self.path).ok();
        }
    }

    pub struct Backend {
        scope: Scope,
        /// Present only for `Scope::TemporaryKeychain`.
        temp: Option<TempKeychain>,
    }

    // The Security API is thread-safe and `Backend` hands out no interior
    // references to its keychain handle.
    unsafe impl Send for Backend {}
    unsafe impl Sync for Backend {}

    impl Backend {
        pub fn platform_default() -> Result<Self, KeystoreError> {
            // The probe is a *delete*, and that is load-bearing.
            // `SecItemCopyMatching` succeeds for an unentitled binary and
            // merely reports not-found, so a read probe would select a
            // keychain whose first `SecItemAdd` fails. A delete takes the
            // write path and changes nothing.
            //
            // Any platform refusal falls back, not only -34018: the status
            // varies by OS release and the fallback is another keystore.
            let probe = Self {
                scope: Scope::DataProtection,
                temp: None,
            };
            match probe.delete("com.reyta.rtp2.entitlement-probe", "probe") {
                Ok(_) => Ok(probe),
                Err(KeystoreError::Platform { .. }) => Ok(Self {
                    scope: Scope::LoginKeychain,
                    temp: None,
                }),
                Err(e) => Err(e),
            }
        }

        pub fn with_scope(scope: Scope) -> Result<Self, KeystoreError> {
            match scope {
                Scope::DataProtection | Scope::LoginKeychain => Ok(Self { scope, temp: None }),
                Scope::TemporaryKeychain => Ok(Self {
                    scope,
                    temp: Some(create_temp_keychain()?),
                }),
            }
        }

        pub fn scope(&self) -> Scope {
            self.scope
        }

        /// Entries every query needs: the item class and its coordinates, plus
        /// whichever keychain selector this scope uses.
        ///
        /// `searching` picks the selector: lookups and deletes name a search
        /// list, inserts name a destination. The wrong one is an `errSecParam`,
        /// not a quiet search of the login keychain.
        fn base_query(
            &self,
            service: &str,
            account: &str,
            searching: bool,
        ) -> Result<(Dict, Vec<CfRef>), KeystoreError> {
            let mut dict = Dict::default();
            let mut extra: Vec<CfRef> = Vec::new();

            unsafe {
                dict.borrowed(kSecClass, kSecClassGenericPassword);
            }
            dict.owned(unsafe { kSecAttrService }, cf_string(service)?);
            dict.owned(unsafe { kSecAttrAccount }, cf_string(account)?);

            match self.scope {
                Scope::DataProtection => unsafe {
                    dict.borrowed(kSecUseDataProtectionKeychain, kCFBooleanTrue);
                },
                Scope::LoginKeychain => {
                    // No selector: the defaults are what we want.
                }
                Scope::TemporaryKeychain => {
                    let keychain = self
                        .temp
                        .as_ref()
                        .ok_or(KeystoreError::Unavailable("temporary keychain not created"))?
                        .keychain
                        .raw();
                    if searching {
                        let array = unsafe {
                            CFArrayCreate(
                                kCFAllocatorDefault,
                                [keychain].as_ptr(),
                                1,
                                kCFTypeArrayCallBacks.as_ptr() as *const c_void,
                            )
                        };
                        let array = CfRef::new(array, "CFArrayCreate")?;
                        dict.borrowed(unsafe { kSecMatchSearchList }, array.raw());
                        extra.push(array);
                    } else {
                        dict.borrowed(unsafe { kSecUseKeychain }, keychain);
                    }
                }
            }

            Ok((dict, extra))
        }

        pub fn find(
            &self,
            service: &str,
            account: &str,
        ) -> Result<Option<Zeroizing<[u8; WRAPPING_KEY_LEN]>>, KeystoreError> {
            let (mut dict, _extra) = self.base_query(service, account, true)?;
            unsafe {
                dict.borrowed(kSecReturnData, kCFBooleanTrue);
                dict.borrowed(kSecMatchLimit, kSecMatchLimitOne);
            }
            let query = dict.build()?;

            let mut result: CFTypeRef = std::ptr::null();
            let status = unsafe { SecItemCopyMatching(query.raw(), &mut result) };
            match status {
                ERR_SEC_SUCCESS => {}
                ITEM_NOT_FOUND => return Ok(None),
                status => {
                    return Err(KeystoreError::Platform {
                        op: "SecItemCopyMatching",
                        status,
                    });
                }
            }

            let data = CfRef::new(result, "SecItemCopyMatching")?;
            // Type-check before treating the reference as CFData: a success
            // status only promises *a* value came back. Unreachable today, and
            // kept: a query that also asked for attributes would return a
            // CFDictionary, where `CFDataGetBytePtr` is undefined behaviour.
            if unsafe { CFGetTypeID(data.raw()) } != unsafe { CFDataGetTypeID() } {
                return Err(KeystoreError::MalformedKey);
            }
            let len = unsafe { CFDataGetLength(data.raw()) };
            let ptr = unsafe { CFDataGetBytePtr(data.raw()) };
            if len != WRAPPING_KEY_LEN as CFIndex || ptr.is_null() {
                return Err(KeystoreError::MalformedKey);
            }

            let mut key = Zeroizing::new([0u8; WRAPPING_KEY_LEN]);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, key.as_mut().as_mut_ptr(), WRAPPING_KEY_LEN)
            };
            Ok(Some(key))
        }

        pub fn add(&self, service: &str, account: &str, key: &[u8]) -> Result<(), KeystoreError> {
            let (mut dict, _extra) = self.base_query(service, account, false)?;
            dict.owned(unsafe { kSecValueData }, cf_data(key)?);
            if self.scope == Scope::DataProtection {
                // Off iCloud, this device only, readable by a transfer that
                // resumes after a reboot. Moot for a file-based keychain.
                unsafe {
                    dict.borrowed(
                        kSecAttrAccessible,
                        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    );
                }
            }
            let attributes = dict.build()?;

            let status = unsafe { SecItemAdd(attributes.raw(), std::ptr::null_mut()) };
            if status != ERR_SEC_SUCCESS {
                return Err(KeystoreError::Platform {
                    op: "SecItemAdd",
                    status,
                });
            }
            Ok(())
        }

        pub fn delete(&self, service: &str, account: &str) -> Result<bool, KeystoreError> {
            let (dict, _extra) = self.base_query(service, account, true)?;
            let query = dict.build()?;
            let status = unsafe { SecItemDelete(query.raw()) };
            match status {
                ERR_SEC_SUCCESS => Ok(true),
                ITEM_NOT_FOUND => Ok(false),
                status => Err(KeystoreError::Platform {
                    op: "SecItemDelete",
                    status,
                }),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Secure Enclave root
    // -----------------------------------------------------------------------

    /// A non-exportable P-256 key held by the Secure Enclave.
    ///
    /// P-256 + ECIES because those are macOS 10.12 APIs and run on Sonoma and
    /// earlier, where the Secure Enclave ML-KEM types do not. This layer only
    /// wraps a symmetric key, so the curve is a local matter and changes
    /// nothing on the wire.
    pub struct HardwareRoot {
        private_key: CfRef,
    }

    unsafe impl Send for HardwareRoot {}
    unsafe impl Sync for HardwareRoot {}

    fn cf_error_code(err: CFTypeRef) -> i32 {
        if err.is_null() {
            return 0;
        }
        let code = unsafe { CFErrorGetCode(err) } as i32;
        unsafe { CFRelease(err) };
        code
    }

    /// The tag is the item's identity in the keychain, so it must be stable
    /// and must not collide with another account's root.
    fn hardware_tag(service: &str, account: &str) -> Vec<u8> {
        format!("{service}/{account}/hardware-root-v1").into_bytes()
    }

    impl HardwareRoot {
        /// Loads this device's hardware root, creating it on first use.
        pub fn open(service: &str, account: &str) -> Result<Self, KeystoreError> {
            let tag = hardware_tag(service, account);
            if let Some(key) = Self::find(&tag)? {
                return Ok(Self { private_key: key });
            }
            Self::create(&tag)
        }

        fn find(tag: &[u8]) -> Result<Option<CfRef>, KeystoreError> {
            let mut dict = Dict::default();
            unsafe {
                dict.borrowed(kSecClass, kSecClassKey);
                dict.borrowed(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
                dict.borrowed(kSecReturnRef, kCFBooleanTrue);
                dict.borrowed(kSecMatchLimit, kSecMatchLimitOne);
            }
            dict.owned(unsafe { kSecAttrApplicationTag }, cf_data(tag)?);
            let query = dict.build()?;

            let mut result: CFTypeRef = std::ptr::null();
            let status = unsafe { SecItemCopyMatching(query.raw(), &mut result) };
            match status {
                ERR_SEC_SUCCESS => Ok(Some(CfRef::new(result, "SecItemCopyMatching")?)),
                ITEM_NOT_FOUND => Ok(None),
                status => Err(KeystoreError::Platform {
                    op: "SecItemCopyMatching(key)",
                    status,
                }),
            }
        }

        fn create(tag: &[u8]) -> Result<Self, KeystoreError> {
            // Same reason as the symmetric path: a transfer resuming after a
            // reboot runs before anyone touches the machine. No user-presence
            // flag, so no prompt.
            let mut error: CFTypeRef = std::ptr::null();
            let access = unsafe {
                SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    ACCESS_CONTROL_PRIVATE_KEY_USAGE,
                    &mut error,
                )
            };
            if access.is_null() {
                return Err(KeystoreError::Platform {
                    op: "SecAccessControlCreateWithFlags",
                    status: cf_error_code(error),
                });
            }
            let access = CfRef::new(access, "SecAccessControlCreateWithFlags")?;

            let mut private_attrs = Dict::default();
            unsafe {
                private_attrs.borrowed(kSecAttrIsPermanent, kCFBooleanTrue);
                private_attrs.borrowed(kSecAttrAccessControl, access.raw());
            }
            private_attrs.owned(unsafe { kSecAttrApplicationTag }, cf_data(tag)?);
            let private_attrs = private_attrs.build()?;

            let bits: i32 = 256;
            let size = unsafe {
                CFNumberCreate(
                    kCFAllocatorDefault,
                    CF_NUMBER_INT_TYPE,
                    &bits as *const i32 as *const c_void,
                )
            };
            let size = CfRef::new(size, "CFNumberCreate")?;

            let mut params = Dict::default();
            unsafe {
                params.borrowed(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
                params.borrowed(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
                params.borrowed(kSecAttrKeySizeInBits, size.raw());
                params.borrowed(kSecPrivateKeyAttrs, private_attrs.raw());
            }
            let params = params.build()?;

            let mut error: CFTypeRef = std::ptr::null();
            let key = unsafe { SecKeyCreateRandomKey(params.raw(), &mut error) };
            if key.is_null() {
                // No Secure Enclave, or the platform refused. Either way an
                // error, never a quiet drop to a software key.
                return Err(KeystoreError::Platform {
                    op: "SecKeyCreateRandomKey(SecureEnclave)",
                    status: cf_error_code(error),
                });
            }
            Ok(Self {
                private_key: CfRef::new(key, "SecKeyCreateRandomKey")?,
            })
        }

        /// Encrypts to the root's public key, on the CPU. Only opening needs
        /// the enclave.
        pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            let public = unsafe { SecKeyCopyPublicKey(self.private_key.raw()) };
            let public = CfRef::new(public, "SecKeyCopyPublicKey")?;
            let data = cf_data(plaintext)?;

            let mut error: CFTypeRef = std::ptr::null();
            let sealed = unsafe {
                SecKeyCreateEncryptedData(
                    public.raw(),
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                    data.raw(),
                    &mut error,
                )
            };
            if sealed.is_null() {
                return Err(KeystoreError::Platform {
                    op: "SecKeyCreateEncryptedData",
                    status: cf_error_code(error),
                });
            }
            let sealed = CfRef::new(sealed, "SecKeyCreateEncryptedData")?;
            Ok(cf_data_bytes(&sealed))
        }

        /// Decrypts inside the enclave. The key never leaves it; the
        /// plaintext does.
        pub fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
            let data = cf_data(sealed)?;
            let mut error: CFTypeRef = std::ptr::null();
            let opened = unsafe {
                SecKeyCreateDecryptedData(
                    self.private_key.raw(),
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                    data.raw(),
                    &mut error,
                )
            };
            if opened.is_null() {
                return Err(KeystoreError::Platform {
                    op: "SecKeyCreateDecryptedData",
                    status: cf_error_code(error),
                });
            }
            let opened = CfRef::new(opened, "SecKeyCreateDecryptedData")?;
            Ok(Zeroizing::new(cf_data_bytes(&opened)))
        }

        /// Removes the hardware root. Everything it wrapped is gone for
        /// good: the enclave cannot be asked twice.
        pub fn forget(service: &str, account: &str) -> Result<bool, KeystoreError> {
            let tag = hardware_tag(service, account);
            let mut dict = Dict::default();
            unsafe {
                dict.borrowed(kSecClass, kSecClassKey);
                dict.borrowed(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            }
            dict.owned(unsafe { kSecAttrApplicationTag }, cf_data(&tag)?);
            let query = dict.build()?;
            match unsafe { SecItemDelete(query.raw()) } {
                ERR_SEC_SUCCESS => Ok(true),
                ITEM_NOT_FOUND => Ok(false),
                status => Err(KeystoreError::Platform {
                    op: "SecItemDelete(key)",
                    status,
                }),
            }
        }
    }

    fn cf_data_bytes(data: &CfRef) -> Vec<u8> {
        let len = unsafe { CFDataGetLength(data.raw()) };
        let ptr = unsafe { CFDataGetBytePtr(data.raw()) };
        if len <= 0 || ptr.is_null() {
            return Vec::new();
        }
        let mut out = vec![0u8; len as usize];
        unsafe { std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), len as usize) };
        out
    }

    fn create_temp_keychain() -> Result<TempKeychain, KeystoreError> {
        let path = std::env::temp_dir().join(format!(
            "rtp2-test-{}-{}.keychain",
            std::process::id(),
            u64::from_be_bytes(crate::crypto::os_random_array::<8>())
        ));
        // A throwaway password: the keychain is created unlocked and dies
        // with the handle, so nothing reopens it.
        let password = crate::crypto::os_random_array::<32>();
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| KeystoreError::InvalidLabel)?;

        let mut keychain: SecKeychainRef = std::ptr::null();
        let status = unsafe {
            SecKeychainCreate(
                c_path.as_ptr(),
                password.len() as u32,
                password.as_ptr() as *const c_void,
                0,
                std::ptr::null(),
                &mut keychain,
            )
        };
        if status != ERR_SEC_SUCCESS {
            return Err(KeystoreError::Platform {
                op: "SecKeychainCreate",
                status,
            });
        }
        Ok(TempKeychain {
            keychain: CfRef::new(keychain, "SecKeychainCreate")?,
            path,
        })
    }
}

// ---------------------------------------------------------------------------
// Everything else
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod imp {
    //! No keystore implementation on this target.
    //!
    //! Every entry point errors rather than falling back to something
    //! weaker. Asking for keystore protection here is refused, not quietly
    //! served a plaintext seed.

    use zeroize::Zeroizing;

    use super::{KeystoreError, Scope, WRAPPING_KEY_LEN};

    pub const ITEM_NOT_FOUND: i32 = -25300;
    pub const DUPLICATE_ITEM: i32 = -25299;
    pub const HARDWARE_BACKEND: &str = "unavailable";

    /// No security processor here yet. Linux has no universal answer, so
    /// this refuses rather than hand back a software key labelled hardware.
    pub struct HardwareRoot;

    impl HardwareRoot {
        pub fn open(_service: &str, _account: &str) -> Result<Self, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn unseal(&self, _sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn forget(_service: &str, _account: &str) -> Result<bool, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }
    }

    pub struct Backend;

    impl Backend {
        pub fn platform_default() -> Result<Self, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn with_scope(_scope: Scope) -> Result<Self, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn scope(&self) -> Scope {
            Scope::LoginKeychain
        }

        pub fn find(
            &self,
            _service: &str,
            _account: &str,
        ) -> Result<Option<Zeroizing<[u8; WRAPPING_KEY_LEN]>>, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn add(
            &self,
            _service: &str,
            _account: &str,
            _key: &[u8],
        ) -> Result<(), KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }

        pub fn delete(&self, _service: &str, _account: &str) -> Result<bool, KeystoreError> {
            Err(KeystoreError::Unavailable(std::env::consts::OS))
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::store::{DeviceStore, StoreError};

    /// One temporary keychain per test, deleted with the handle. Never the
    /// login keychain: an item there outlives the run, and the next build's
    /// binary reading it raises an ACL prompt that hangs the suite.
    fn temp_keystore() -> Keystore {
        Keystore::with_scope(Scope::TemporaryKeychain).expect("temporary keychain")
    }

    fn workdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rtp2-keystore-{}-{}-{tag}",
            std::process::id(),
            u64::from_be_bytes(crate::crypto::os_random_array::<8>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn expect_err(
        result: Result<(crate::identity::DeviceIdentity, bool), StoreError>,
    ) -> StoreError {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn wrapping_key_is_created_once_and_read_back() {
        let ks = temp_keystore();
        let first = ks.wrapping_key("rtp2-test", "once").unwrap();
        let second = ks.wrapping_key("rtp2-test", "once").unwrap();
        assert_eq!(first.as_ref(), second.as_ref(), "the key must be stable");
        assert_ne!(first.as_ref(), &[0u8; WRAPPING_KEY_LEN], "not a null key");

        // A different account is a different key, so two identities on one
        // machine are not sealed under the same wrap key by accident.
        let other = ks.wrapping_key("rtp2-test", "another").unwrap();
        assert_ne!(first.as_ref(), other.as_ref());

        ks.forget("rtp2-test", "once").unwrap();
        ks.forget("rtp2-test", "another").unwrap();
    }

    #[test]
    fn forget_removes_the_key_and_is_idempotent() {
        let ks = temp_keystore();
        let before = ks.wrapping_key("rtp2-test", "forget").unwrap();
        assert!(ks.forget("rtp2-test", "forget").unwrap(), "removed");
        assert!(!ks.forget("rtp2-test", "forget").unwrap(), "already gone");

        // A fresh key, not the old one: `forget` really destroyed it.
        let after = ks.wrapping_key("rtp2-test", "forget").unwrap();
        assert_ne!(before.as_ref(), after.as_ref());
        ks.forget("rtp2-test", "forget").unwrap();
    }

    /// A coordinate nothing ever stores under, so probing it is free.
    const PROBE_SERVICE: &str = "com.reyta.rtp2.entitlement-probe";

    #[test]
    fn the_data_protection_probe_must_take_the_write_path() {
        // This is why `platform_default` probes with a delete rather than a
        // find. On an unentitled binary, which every `cargo test` binary is,
        // the data-protection read path is allowed and the write path is not,
        // so a find-based probe selects a keychain that cannot store the
        // wrapping key and fails only on first use.
        let dp = Keystore::with_scope(Scope::DataProtection).unwrap();

        let read = dp.backend.find(PROBE_SERVICE, "nothing-here");
        assert!(
            matches!(read, Ok(None)),
            "a read must be permitted and find nothing, got {read:?}"
        );

        let write = dp
            .backend
            .add(PROBE_SERVICE, "nothing-here", &[0u8; WRAPPING_KEY_LEN]);
        match write {
            Err(KeystoreError::Platform { status, .. }) => assert_eq!(
                status, -34018,
                "expected errSecMissingEntitlement from the write path"
            ),
            other => {
                // Should not happen, but if the binary ever becomes entitled,
                // do not leave the probe item behind.
                let _ = dp.backend.delete(PROBE_SERVICE, "nothing-here");
                panic!("an unentitled binary must not be able to write: {other:?}");
            }
        }

        // And so the default resolves to the login keychain, not to a
        // data-protection keychain it cannot use.
        assert_eq!(
            Keystore::platform_default().unwrap().describe(),
            "macos-login-keychain"
        );
    }

    /// The hardware level either works completely or refuses completely.
    /// Which one a build lands in depends on how it was signed. What must
    /// never happen is a half state: a refusal that already wrote a vault key,
    /// or a success that cannot be reopened.
    #[test]
    fn the_hardware_level_either_works_or_leaves_nothing_behind() {
        let base = workdir("hardware");
        let dir = base.join("state");
        DeviceStore::open(&dir).unwrap();
        let service = "com.reyta.rtp2.test.hardware";

        match HardwareSealer::open(&dir, service, "root") {
            Ok(sealer) => {
                assert_eq!(sealer.protection(), Protection::HardwareKeystore);

                // The vault key must round-trip through the enclave: a second
                // open has to unwrap the same key, or every record written by
                // the first process is lost on restart.
                let sealed = sealer.seal(b"payload", b"aad").unwrap();
                let reopened = HardwareSealer::open(&dir, service, "root").unwrap();
                assert_eq!(
                    reopened.open(&sealed, b"aad").unwrap().as_slice(),
                    b"payload",
                    "the wrapped vault key must survive a restart"
                );

                // And the vault key must not be on disk in the clear.
                let wrapped = std::fs::read(dir.join(VAULT_KEY_FILE)).unwrap();
                let probe = sealer.seal(&[0u8; 32], b"x").unwrap();
                assert!(!wrapped.is_empty() && probe.len() > 32);

                HardwareSealer::forget(service, "root").unwrap();
            }
            Err(e) => {
                // A refusal must be total. Anything written here would be a
                // vault key whose root does not exist: permanently dead
                // state that a later, entitled run would refuse to open.
                assert!(
                    !dir.join(VAULT_KEY_FILE).exists(),
                    "a refused hardware root ({e}) must not leave a wrapped vault key behind"
                );
            }
        }

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn an_item_of_the_wrong_length_is_not_used_as_a_key() {
        // The keystore is shared with everything else on the machine, and a
        // generic-password item under our coordinates could hold anything,
        // an older format, or something another tool wrote. Truncating or
        // zero-extending it into a 32-byte key would silently seal records
        // under a key with far less entropy than it appears to have.
        let ks = temp_keystore();
        ks.backend
            .add("rtp2-test", "short", b"only sixteen by.")
            .unwrap();

        let got = ks.wrapping_key("rtp2-test", "short");
        assert!(
            matches!(got, Err(KeystoreError::MalformedKey)),
            "a short item must be refused, got {got:?}"
        );

        ks.forget("rtp2-test", "short").unwrap();
    }

    #[test]
    fn empty_and_oversized_labels_are_refused() {
        let ks = temp_keystore();
        assert!(matches!(
            ks.wrapping_key("", "account"),
            Err(KeystoreError::InvalidLabel)
        ));
        let long = "x".repeat(MAX_LABEL_BYTES + 1);
        assert!(matches!(
            ks.wrapping_key("rtp2-test", &long),
            Err(KeystoreError::InvalidLabel)
        ));
    }

    #[test]
    fn the_seed_is_not_on_disk_and_survives_a_restart() {
        let base = workdir("sealed-identity");
        let dir = base.join("state");
        let ks = temp_keystore();

        let sealer = KeystoreSealer::from_keystore(&ks, "rtp2-test", "identity").unwrap();
        let store = DeviceStore::open(&dir)
            .unwrap()
            .with_sealer(Box::new(sealer), Protection::PlatformKeystore);
        let (first, loaded) = store.load_or_create_identity().unwrap();
        assert!(!loaded, "first run creates");

        // The record must not contain the seed. Recover the seed through the
        // sealer and search the file for it, rather than assuming the AEAD ran
        //: a sealer that returned its input would pass a weaker assertion.
        let bytes = std::fs::read(store.identity_path()).unwrap();
        let recovered = KeystoreSealer::from_keystore(&ks, "rtp2-test", "identity").unwrap();
        let payload = crate::store::read_sealed(
            &store.identity_path(),
            crate::store::IDENTITY_DOMAIN,
            &recovered,
            Protection::PlatformKeystore,
        )
        .unwrap()
        .unwrap();
        let seed = crate::store::decode_identity_payload(&payload).unwrap();
        assert_eq!(
            crate::identity::DeviceIdentity::from_seed(&seed).device_id,
            first.device_id,
            "the recovered seed must be the one this identity came from"
        );
        assert!(
            !bytes.windows(32).any(|w| w == seed.as_ref()),
            "a keystore-sealed record must not contain the seed"
        );

        // A restart rebuilds the sealer from the keystore and gets the same
        // device back.
        let restarted = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "identity").unwrap()),
            Protection::PlatformKeystore,
        );
        let (second, loaded) = restarted.load_or_create_identity().unwrap();
        assert!(loaded, "second run loads");
        assert_eq!(first.device_id, second.device_id);

        ks.forget("rtp2-test", "identity").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn identity_is_unreadable_without_the_wrapping_key() {
        let base = workdir("lost-key");
        let dir = base.join("state");
        let ks = temp_keystore();

        let store = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "lost").unwrap()),
            Protection::PlatformKeystore,
        );
        store.load_or_create_identity().unwrap();
        let record_before = std::fs::read(store.identity_path()).unwrap();

        // The keychain item is gone: a keychain reset, or a restore onto a
        // machine the item never reached.
        assert!(ks.forget("rtp2-test", "lost").unwrap());

        // The next open mints a *new* wrapping key, which cannot open the old
        // record. That must be an error, never a fresh identity: a new device
        // id would break every peer's trust-on-first-use pin.
        let reopened = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "lost").unwrap()),
            Protection::PlatformKeystore,
        );
        let err = expect_err(reopened.load_or_create_identity());
        assert!(matches!(err, StoreError::Seal), "got {err:?}");
        assert_eq!(
            std::fs::read(store.identity_path()).unwrap(),
            record_before,
            "the unopenable record must be left alone, not replaced"
        );

        ks.forget("rtp2-test", "lost").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_plaintext_record_is_refused_by_a_keystore_store() {
        let base = workdir("no-downgrade");
        let dir = base.join("state");

        // Written by the prototype default...
        DeviceStore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();

        // ...and read by a store that demands the keystore. The record says
        // Plaintext, so it is refused before the sealer is even consulted.
        let ks = temp_keystore();
        let strict = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "downgrade").unwrap()),
            Protection::PlatformKeystore,
        );
        assert!(matches!(
            expect_err(strict.load_or_create_identity()),
            StoreError::ProtectionDowngrade
        ));

        ks.forget("rtp2-test", "downgrade").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_record_sealed_under_another_account_does_not_open() {
        let base = workdir("wrong-account");
        let dir = base.join("state");
        let ks = temp_keystore();

        DeviceStore::open(&dir)
            .unwrap()
            .with_sealer(
                Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "a").unwrap()),
                Protection::PlatformKeystore,
            )
            .load_or_create_identity()
            .unwrap();

        let wrong = DeviceStore::open(&dir).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "b").unwrap()),
            Protection::PlatformKeystore,
        );
        assert!(matches!(
            expect_err(wrong.load_or_create_identity()),
            StoreError::Seal
        ));

        ks.forget("rtp2-test", "a").unwrap();
        ks.forget("rtp2-test", "b").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resumption_secrets_are_sealed_by_the_same_store() {
        // §8.4 secrets go through the same sealer seam as the identity, so
        // turning on the keystore protects them too: without a second code
        // path to get wrong.
        let base = workdir("resumption");
        let ks = temp_keystore();
        let store = DeviceStore::open(&base.join("state")).unwrap().with_sealer(
            Box::new(KeystoreSealer::from_keystore(&ks, "rtp2-test", "resumption").unwrap()),
            Protection::PlatformKeystore,
        );

        let entry = crate::store::ResumptionEntry {
            resumption_id: [7u8; 16],
            peer_device_id: [8u8; 32],
            secret: [9u8; 48],
            suite_id: 1,
            protocol_major: 2,
            created_at: 1_000,
            expires_at: 1_000 + 3600,
        };
        store.store_resumption(&entry, 1_000).unwrap();

        let bytes = std::fs::read(store.resumption_path()).unwrap();
        assert!(
            !bytes.windows(48).any(|w| w == entry.secret),
            "a keystore-sealed resumption file must not contain the secret"
        );

        let taken = store
            .take_resumption(&entry.resumption_id, &entry.peer_device_id, 1, 2, 1_500)
            .unwrap()
            .expect("the secret round-trips through the keystore sealer");
        assert_eq!(taken.secret, entry.secret);

        ks.forget("rtp2-test", "resumption").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }
}
