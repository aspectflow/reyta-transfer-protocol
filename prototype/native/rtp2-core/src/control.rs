// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Control-frame protection and key epochs (§17.1.1–§17.1.2).
//!
//! §8.2.9 derives the two control keys; this is where they get used. After
//! the handshake nothing goes out in the clear, and the protection rekeys so
//! a long session never exhausts a counter under one key.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, PROTOCOL_MAJOR, SUITE_ID};

/// derive_key context, distinct from every other one in the project.
const CONTROL_NONCE_CONTEXT: &str = "Reyta RTP2 2026-08-01 control nonce v1";
const EPOCH_SALT_DOMAIN: &[u8] = b"RTP2-EPOCH-SALT-v1";
const CONTROL_AAD_MAGIC: &[u8; 8] = b"RTP2CTRL";

/// §17.1.2: a sender MUST begin a new epoch before the counter reaches 2^32.
pub const MAX_FRAMES_PER_EPOCH: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Initiator to responder.
    ClientToServer = 0,
    /// Responder to initiator.
    ServerToClient = 1,
}

impl Direction {
    fn byte(self) -> u8 {
        self as u8
    }

    fn opposite(self) -> Self {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// AEAD verification failed, or the frame was malformed.
    Decrypt,
    /// A counter already accepted in this epoch was presented again.
    Replay,
    /// A frame named an epoch below the current one.
    StaleEpoch,
    /// A frame named an epoch more than one above the current one.
    EpochGap,
    /// The send counter is exhausted; rekey before sending more.
    CounterExhausted,
    Malformed,
}

/// §17.1.2 epoch chain, every epoch derived from `handshake_prk` and TH2. Two
/// peers cannot drift apart: miss a REKEY and you simply cannot decrypt.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EpochKeys {
    #[zeroize(skip)]
    epoch: u64,
    c2s: [u8; 32],
    s2c: [u8; 32],
}

impl EpochKeys {
    fn key_for(&self, direction: Direction) -> &[u8; 32] {
        match direction {
            Direction::ClientToServer => &self.c2s,
            Direction::ServerToClient => &self.s2c,
        }
    }
}

/// Per-session control state: the epoch chain, plus the counters that keep
/// every (key, nonce) pair single-use.
pub struct ControlChannel {
    /// Which direction this endpoint sends in.
    send_direction: Direction,
    /// Root of the chain: `epoch_prk_n`, advanced on rekey.
    epoch_prk: Zeroizing<[u8; 48]>,
    th2: [u8; 48],
    keys: EpochKeys,
    send_counter: u64,
    /// One past the highest accepted receive counter this epoch. Strictly
    /// increasing counters refuse replays without keeping a window.
    receive_watermark: u64,
}

impl ControlChannel {
    /// Starts at epoch 0, whose keys are exactly the §8.2.9 keys.
    pub fn new(handshake_prk: &[u8; 48], th2: &[u8; 48], send_direction: Direction) -> Self {
        let keys = derive_epoch(handshake_prk, th2, 0);
        Self {
            send_direction,
            epoch_prk: Zeroizing::new(*handshake_prk),
            th2: *th2,
            keys,
            send_counter: 0,
            receive_watermark: 0,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.keys.epoch
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Seals a frame, returning the epoch and counter the receiver needs to
    /// rebuild the nonce.
    pub fn seal(
        &mut self,
        frame_type: u8,
        frame_flags: u8,
        request_id: u64,
        plaintext: &[u8],
    ) -> Result<SealedFrame, ControlError> {
        if self.send_counter >= MAX_FRAMES_PER_EPOCH {
            return Err(ControlError::CounterExhausted);
        }
        let epoch = self.keys.epoch;
        let counter = self.send_counter;
        let aad = control_aad(
            self.send_direction,
            epoch,
            counter,
            frame_type,
            frame_flags,
            request_id,
        );
        let ciphertext = seal_with(
            self.keys.key_for(self.send_direction),
            self.send_direction,
            epoch,
            counter,
            &aad,
            plaintext,
        )?;
        self.send_counter += 1;
        Ok(SealedFrame {
            epoch,
            counter,
            ciphertext,
        })
    }

    /// Opens a frame. A failing frame advances no state, neither watermark
    /// nor epoch, which is what makes rejection side-effect free (INV-24).
    pub fn open(
        &mut self,
        epoch: u64,
        counter: u64,
        frame_type: u8,
        frame_flags: u8,
        request_id: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ControlError> {
        let direction = self.send_direction.opposite();

        // Epoch policy first: cheap, and it bounds the work below.
        if epoch < self.keys.epoch {
            return Err(ControlError::StaleEpoch);
        }
        if epoch > self.keys.epoch + 1 {
            return Err(ControlError::EpochGap);
        }

        // Next epoch means the peer rekeyed. Derive it, but do not adopt
        // until the frame verifies.
        let candidate = if epoch == self.keys.epoch {
            None
        } else {
            let next_prk = advance_prk(&self.epoch_prk, epoch);
            Some((derive_epoch(&next_prk, &self.th2, epoch), next_prk))
        };

        // Counters strictly increase within an epoch. A new epoch restarts
        // them, so the watermark is per-epoch.
        if candidate.is_none() && counter < self.receive_watermark {
            return Err(ControlError::Replay);
        }
        if counter >= MAX_FRAMES_PER_EPOCH {
            return Err(ControlError::Malformed);
        }

        let key = match &candidate {
            Some((keys, _)) => *keys.key_for(direction),
            None => *self.keys.key_for(direction),
        };
        let aad = control_aad(
            direction,
            epoch,
            counter,
            frame_type,
            frame_flags,
            request_id,
        );
        let plaintext = open_with(&key, direction, epoch, counter, &aad, ciphertext)?;

        // Only now does state move.
        if let Some((keys, prk)) = candidate {
            // Old epoch keys go once a frame in the new one is accepted.
            // `EpochKeys` is ZeroizeOnDrop.
            self.keys = keys;
            self.epoch_prk = prk;
            self.send_counter = 0;
            self.receive_watermark = 0;
        }
        self.receive_watermark = counter + 1;
        Ok(plaintext)
    }

    /// Starts the next send epoch. The peer switches on the first frame it
    /// sees in it.
    ///
    /// **Not called by the transfer path, and calling it there would break the
    /// session.** The epoch belongs to the channel, not to a direction, so this
    /// advances both: afterwards a frame arriving from the peer in the old
    /// epoch fails `open` with `StaleEpoch`. In a transfer that is the
    /// receiver's final acknowledgement, and the transfer would fail after
    /// every chunk had already arrived.
    ///
    /// A rekey therefore has to be negotiated — the REKEY frame in §17.4
    /// exists for that — and until it is, this is the derivation half of the
    /// mechanism with the coordination half missing. It is exercised by this
    /// module's tests and by nothing else.
    ///
    /// The threshold is out of reach in the meantime: at 2^32 frames of 256 KiB
    /// a session would have to carry an exabyte before `rekey_due` fired.
    pub fn begin_next_epoch(&mut self) {
        let next = self.keys.epoch + 1;
        let prk = advance_prk(&self.epoch_prk, next);
        self.keys = derive_epoch(&prk, &self.th2, next);
        self.epoch_prk = prk;
        self.send_counter = 0;
        self.receive_watermark = 0;
    }

    /// Whether to send REKEY before the counter actually runs out.
    ///
    /// Unreachable in a transfer, for the reason given on `begin_next_epoch`.
    /// Kept because §17.1.2 makes beginning a new epoch before 2^32 a MUST,
    /// and the arithmetic that decides when should live next to the counter it
    /// reads, not in whichever caller eventually implements the negotiation.
    pub fn rekey_due(&self) -> bool {
        self.send_counter + 1024 >= MAX_FRAMES_PER_EPOCH
    }
}

pub struct SealedFrame {
    pub epoch: u64,
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

fn advance_prk(current: &[u8; 48], next_epoch: u64) -> Zeroizing<[u8; 48]> {
    let mut salt = Vec::with_capacity(EPOCH_SALT_DOMAIN.len() + 8);
    salt.extend_from_slice(EPOCH_SALT_DOMAIN);
    salt.extend_from_slice(&next_epoch.to_be_bytes());
    crypto::hkdf_extract(&salt, current)
}

fn derive_epoch(prk: &[u8; 48], th2: &[u8; 48], epoch: u64) -> EpochKeys {
    EpochKeys {
        epoch,
        c2s: *crypto::hkdf_expand::<32>(prk, &[b"RTP2 control c2s v1", th2]),
        s2c: *crypto::hkdf_expand::<32>(prk, &[b"RTP2 control s2c v1", th2]),
    }
}

/// §17.1.1 nonce derivation.
pub fn control_nonce(direction: Direction, epoch: u64, counter: u64) -> [u8; 24] {
    let mut material = [0u8; 17];
    material[0] = direction.byte();
    material[1..9].copy_from_slice(&epoch.to_be_bytes());
    material[9..17].copy_from_slice(&counter.to_be_bytes());
    let derived = blake3::derive_key(CONTROL_NONCE_CONTEXT, &material);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&derived[..24]);
    nonce
}

/// §17.1.1 associated data. Fixed 39-byte layout.
pub fn control_aad(
    direction: Direction,
    epoch: u64,
    counter: u64,
    frame_type: u8,
    frame_flags: u8,
    request_id: u64,
) -> [u8; 39] {
    let mut aad = [0u8; 39];
    aad[0..8].copy_from_slice(CONTROL_AAD_MAGIC);
    aad[8..10].copy_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
    aad[10..12].copy_from_slice(&SUITE_ID.to_be_bytes());
    aad[12] = direction.byte();
    aad[13..21].copy_from_slice(&epoch.to_be_bytes());
    aad[21..29].copy_from_slice(&counter.to_be_bytes());
    aad[29] = frame_type;
    aad[30] = frame_flags;
    aad[31..39].copy_from_slice(&request_id.to_be_bytes());
    aad
}

fn seal_with(
    key: &[u8; 32],
    direction: Direction,
    epoch: u64,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ControlError> {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ControlError::Decrypt)?;
    let nonce = control_nonce(direction, epoch, counter);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ControlError::Decrypt)
}

fn open_with(
    key: &[u8; 32],
    direction: Direction,
    epoch: u64,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ControlError> {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ControlError::Decrypt)?;
    let nonce = control_nonce(direction, epoch, counter);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ControlError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (ControlChannel, ControlChannel) {
        let prk = [0x11u8; 48];
        let th2 = [0x22u8; 48];
        (
            ControlChannel::new(&prk, &th2, Direction::ClientToServer),
            ControlChannel::new(&prk, &th2, Direction::ServerToClient),
        )
    }

    #[test]
    fn epoch_zero_matches_the_section_8_2_9_keys() {
        // A session that never rekeys must look exactly like the old
        // behaviour, so epoch 0 is the plain §8.2.9 derivation.
        let prk = [0x33u8; 48];
        let th2 = [0x44u8; 48];
        let keys = derive_epoch(&prk, &th2, 0);
        assert_eq!(
            keys.c2s,
            *crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control c2s v1", &th2])
        );
        assert_eq!(
            keys.s2c,
            *crypto::hkdf_expand::<32>(&prk, &[b"RTP2 control s2c v1", &th2])
        );
        assert_ne!(keys.c2s, keys.s2c, "directions must not share a key");
    }

    #[test]
    fn roundtrip_in_both_directions() {
        let (mut client, mut server) = pair();

        let sealed = client.seal(0x05, 0, 7, b"range request").unwrap();
        let opened = server
            .open(sealed.epoch, sealed.counter, 0x05, 0, 7, &sealed.ciphertext)
            .unwrap();
        assert_eq!(opened, b"range request");

        let sealed = server.seal(0x0A, 0, 7, b"complete").unwrap();
        let opened = client
            .open(sealed.epoch, sealed.counter, 0x0A, 0, 7, &sealed.ciphertext)
            .unwrap();
        assert_eq!(opened, b"complete");
    }

    #[test]
    fn every_aad_field_is_bound() {
        let (mut client, mut server) = pair();
        let sealed = client.seal(0x05, 0, 42, b"payload").unwrap();

        // Wrong frame type, flags, or request id all fail.
        assert_eq!(
            server
                .open(
                    sealed.epoch,
                    sealed.counter,
                    0x06,
                    0,
                    42,
                    &sealed.ciphertext
                )
                .unwrap_err(),
            ControlError::Decrypt
        );
        assert_eq!(
            server
                .open(
                    sealed.epoch,
                    sealed.counter,
                    0x05,
                    1,
                    42,
                    &sealed.ciphertext
                )
                .unwrap_err(),
            ControlError::Decrypt
        );
        assert_eq!(
            server
                .open(
                    sealed.epoch,
                    sealed.counter,
                    0x05,
                    0,
                    43,
                    &sealed.ciphertext
                )
                .unwrap_err(),
            ControlError::Decrypt
        );
        // A tampered ciphertext fails.
        let mut bad = sealed.ciphertext.clone();
        bad[0] ^= 1;
        assert_eq!(
            server
                .open(sealed.epoch, sealed.counter, 0x05, 0, 42, &bad)
                .unwrap_err(),
            ControlError::Decrypt
        );
        // After all those failures the honest frame still opens: nothing
        // advanced (INV-24).
        assert_eq!(
            server
                .open(
                    sealed.epoch,
                    sealed.counter,
                    0x05,
                    0,
                    42,
                    &sealed.ciphertext
                )
                .unwrap(),
            b"payload"
        );
    }

    #[test]
    fn counters_must_strictly_increase() {
        let (mut client, mut server) = pair();
        let first = client.seal(0x05, 0, 1, b"one").unwrap();
        let second = client.seal(0x05, 0, 2, b"two").unwrap();
        assert_eq!(first.counter, 0);
        assert_eq!(second.counter, 1);

        server
            .open(second.epoch, second.counter, 0x05, 0, 2, &second.ciphertext)
            .unwrap();
        // The earlier frame is now a replay.
        assert_eq!(
            server
                .open(first.epoch, first.counter, 0x05, 0, 1, &first.ciphertext)
                .unwrap_err(),
            ControlError::Replay
        );
        // And so is the one just accepted.
        assert_eq!(
            server
                .open(second.epoch, second.counter, 0x05, 0, 2, &second.ciphertext)
                .unwrap_err(),
            ControlError::Replay
        );
    }

    #[test]
    fn direction_keys_do_not_interchange() {
        // A frame sealed for c2s must not open as if it were s2c.
        let (mut client, mut server) = pair();
        let sealed = client.seal(0x05, 0, 1, b"payload").unwrap();
        // The client opening its own frame means treating it as s2c.
        assert_eq!(
            client
                .open(sealed.epoch, sealed.counter, 0x05, 0, 1, &sealed.ciphertext)
                .unwrap_err(),
            ControlError::Decrypt
        );
        // The server, reading in the right direction, succeeds.
        assert!(
            server
                .open(sealed.epoch, sealed.counter, 0x05, 0, 1, &sealed.ciphertext)
                .is_ok()
        );
    }

    #[test]
    fn peers_converge_across_a_rekey() {
        let (mut client, mut server) = pair();
        // Traffic in epoch 0.
        let f = client.seal(0x05, 0, 1, b"epoch zero").unwrap();
        server
            .open(f.epoch, f.counter, 0x05, 0, 1, &f.ciphertext)
            .unwrap();

        // Client rekeys and sends; the server adopts on receipt.
        client.begin_next_epoch();
        assert_eq!(client.epoch(), 1);
        assert_eq!(server.epoch(), 0);
        let f = client.seal(0x05, 0, 2, b"epoch one").unwrap();
        assert_eq!(f.epoch, 1);
        assert_eq!(f.counter, 0, "counters restart in a new epoch");
        let opened = server
            .open(f.epoch, f.counter, 0x05, 0, 2, &f.ciphertext)
            .unwrap();
        assert_eq!(opened, b"epoch one");
        assert_eq!(server.epoch(), 1);

        // The server can now answer in epoch 1 and the client understands it.
        let back = server.seal(0x0A, 0, 2, b"ack").unwrap();
        assert_eq!(back.epoch, 1);
        assert_eq!(
            client
                .open(back.epoch, back.counter, 0x0A, 0, 2, &back.ciphertext)
                .unwrap(),
            b"ack"
        );
    }

    #[test]
    fn stale_and_far_future_epochs_are_refused() {
        let (mut client, mut server) = pair();
        client.begin_next_epoch();
        let f = client.seal(0x05, 0, 1, b"one").unwrap();
        server
            .open(f.epoch, f.counter, 0x05, 0, 1, &f.ciphertext)
            .unwrap();
        assert_eq!(server.epoch(), 1);

        // Epoch 0 is now stale.
        assert_eq!(
            server.open(0, 0, 0x05, 0, 1, &f.ciphertext).unwrap_err(),
            ControlError::StaleEpoch
        );
        // Two epochs ahead is a gap, which §17.1.2 says terminates.
        assert_eq!(
            server.open(3, 0, 0x05, 0, 1, &f.ciphertext).unwrap_err(),
            ControlError::EpochGap
        );
    }

    #[test]
    fn old_epoch_keys_do_not_open_new_epoch_frames() {
        let prk = [0x55u8; 48];
        let th2 = [0x66u8; 48];
        let e0 = derive_epoch(&prk, &th2, 0);
        let next = advance_prk(&prk, 1);
        let e1 = derive_epoch(&next, &th2, 1);
        assert_ne!(e0.c2s, e1.c2s);
        assert_ne!(e0.s2c, e1.s2c);
        // And the chain is one-way: epoch 1's PRK is not the epoch 0 PRK.
        assert_ne!(next.as_ref(), &prk);
    }

    #[test]
    fn nonce_context_is_distinct_from_every_other_derive_key_use() {
        // A nonce collision across contexts would reuse a (key, nonce) pair.
        let domains: [&[u8]; 4] = [
            CONTROL_NONCE_CONTEXT.as_bytes(),
            b"Reyta RTP2 2026-08-01 chunk nonce v1",
            crate::merkle::LEAF_DOMAIN,
            crate::merkle::NODE_DOMAIN,
        ];
        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(domains[i], domains[j], "contexts {i}/{j} collide");
            }
        }

        // Nonces are unique across direction, epoch and counter.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            for epoch in 0..4u64 {
                for counter in 0..64u64 {
                    assert!(
                        seen.insert(control_nonce(direction, epoch, counter)),
                        "nonce collision at {direction:?}/{epoch}/{counter}"
                    );
                }
            }
        }
    }

    #[test]
    fn aad_layout_matches_the_spec() {
        let aad = control_aad(Direction::ServerToClient, 3, 9, 0x21, 0x01, 0xdead);
        assert_eq!(aad.len(), 39);
        assert_eq!(&aad[0..8], b"RTP2CTRL");
        assert_eq!(&aad[8..10], &2u16.to_be_bytes());
        assert_eq!(&aad[10..12], &1u16.to_be_bytes());
        assert_eq!(aad[12], 1);
        assert_eq!(&aad[13..21], &3u64.to_be_bytes());
        assert_eq!(&aad[21..29], &9u64.to_be_bytes());
        assert_eq!(aad[29], 0x21);
        assert_eq!(aad[30], 0x01);
        assert_eq!(&aad[31..39], &0xdeadu64.to_be_bytes());
    }
}
