// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! RTP-CBOR: the strict deterministic CBOR subset (§13.4).
//!
//! Definite lengths only, unsigned map keys in strictly increasing order,
//! shortest-form integers, no floats, depth <= 16, control objects <= 1 MiB.

pub const MAX_DEPTH: usize = 16;
pub const MAX_CONTROL_SIZE: usize = 1024 * 1024;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

/// The only two simple values RTP-CBOR admits (§13.4.1).
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    Truncated,
    NonCanonical,
    ForbiddenType,
    DepthExceeded,
    SizeExceeded,
    KeyOrder,
    UnexpectedType,
    TrailingBytes,
    MissingField(u64),
    InvalidUtf8,
    InvalidValue,
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Deterministic RTP-CBOR writer. All emit paths use shortest-form headers.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn header(&mut self, major: u8, value: u64) {
        let m = major << 5;
        if value < 24 {
            self.out.push(m | value as u8);
        } else if value <= u8::MAX as u64 {
            self.out.push(m | 24);
            self.out.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.out.push(m | 25);
            self.out.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.out.push(m | 26);
            self.out.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.out.push(m | 27);
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    pub fn uint(&mut self, value: u64) {
        self.header(MAJOR_UINT, value);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.header(MAJOR_BYTES, value.len() as u64);
        self.out.extend_from_slice(value);
    }

    pub fn text(&mut self, value: &str) {
        self.header(MAJOR_TEXT, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
    }

    pub fn boolean(&mut self, value: bool) {
        self.out
            .push((MAJOR_SIMPLE << 5) | if value { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }

    pub fn array(&mut self, len: u64) {
        self.header(MAJOR_ARRAY, len);
    }

    pub fn map(&mut self, len: u64) {
        self.header(MAJOR_MAP, len);
    }
}

/// Map writer that enforces strictly increasing unsigned integer keys.
pub struct MapWriter<'a> {
    w: &'a mut Writer,
    remaining: u64,
    last_key: Option<u64>,
}

impl<'a> MapWriter<'a> {
    pub fn begin(w: &'a mut Writer, entries: u64) -> Self {
        w.map(entries);
        Self {
            w,
            remaining: entries,
            last_key: None,
        }
    }

    fn key(&mut self, key: u64) {
        assert!(self.remaining > 0, "rtp-cbor: too many map entries");
        if let Some(last) = self.last_key {
            assert!(key > last, "rtp-cbor: map keys must strictly increase");
        }
        self.last_key = Some(key);
        self.remaining -= 1;
        self.w.uint(key);
    }

    pub fn uint(&mut self, key: u64, value: u64) {
        self.key(key);
        self.w.uint(value);
    }

    pub fn bytes(&mut self, key: u64, value: &[u8]) {
        self.key(key);
        self.w.bytes(value);
    }

    pub fn boolean(&mut self, key: u64, value: bool) {
        self.key(key);
        self.w.boolean(value);
    }

    pub fn text(&mut self, key: u64, value: &str) {
        self.key(key);
        self.w.text(value);
    }

    /// Emits the key, then hands the raw writer over for a nested value.
    pub fn nested(&mut self, key: u64) -> &mut Writer {
        self.key(key);
        self.w
    }

    pub fn end(self) {
        assert!(self.remaining == 0, "rtp-cbor: missing map entries");
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Strict RTP-CBOR reader. Rejects everything outside the deterministic subset.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, CborError> {
        if buf.len() > MAX_CONTROL_SIZE {
            return Err(CborError::SizeExceeded);
        }
        Ok(Self {
            buf,
            pos: 0,
            depth: 0,
        })
    }

    /// For chunk records, where the 1 MiB cap does not apply. Depth and
    /// canonicality still do.
    pub fn new_unbounded(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    pub fn finish(&self) -> Result<(), CborError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes)
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if self.buf.len() - self.pos < n {
            return Err(CborError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let ai = first & 0x1f;
        let value = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.take(1)?[0] as u64;
                if v < 24 {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v <= u8::MAX as u64 {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= u16::MAX as u64 {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v <= u32::MAX as u64 {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            // 28..=30 reserved, 31 indefinite: neither is RTP-CBOR.
            _ => return Err(CborError::ForbiddenType),
        };
        // Major type 7 admits only true and false. Floats and every other
        // simple value are rejected (§13.4.1).
        if major == MAJOR_SIMPLE && value != SIMPLE_FALSE as u64 && value != SIMPLE_TRUE as u64 {
            return Err(CborError::ForbiddenType);
        }
        Ok((major, value))
    }

    pub fn boolean(&mut self) -> Result<bool, CborError> {
        let (major, value) = self.head()?;
        if major != MAJOR_SIMPLE {
            return Err(CborError::UnexpectedType);
        }
        Ok(value == SIMPLE_TRUE as u64)
    }

    /// Peeks the next major type, for skipping extension values whose shape
    /// we do not know.
    pub fn peek_major(&self) -> Result<u8, CborError> {
        if self.pos >= self.buf.len() {
            return Err(CborError::Truncated);
        }
        Ok(self.buf[self.pos] >> 5)
    }

    pub fn uint(&mut self) -> Result<u64, CborError> {
        let (major, value) = self.head()?;
        if major != MAJOR_UINT {
            return Err(CborError::UnexpectedType);
        }
        Ok(value)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        let (major, len) = self.head()?;
        if major != MAJOR_BYTES {
            return Err(CborError::UnexpectedType);
        }
        self.take(len as usize)
    }

    pub fn bytes_exact<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let raw = self.bytes()?;
        raw.try_into().map_err(|_| CborError::InvalidValue)
    }

    pub fn text(&mut self) -> Result<&'a str, CborError> {
        let (major, len) = self.head()?;
        if major != MAJOR_TEXT {
            return Err(CborError::UnexpectedType);
        }
        let raw = self.take(len as usize)?;
        std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)
    }

    pub fn array(&mut self) -> Result<u64, CborError> {
        let (major, len) = self.head()?;
        if major != MAJOR_ARRAY {
            return Err(CborError::UnexpectedType);
        }
        self.enter()?;
        Ok(len)
    }

    pub fn map(&mut self) -> Result<MapReader<'a, '_>, CborError> {
        let (major, len) = self.head()?;
        if major != MAJOR_MAP {
            return Err(CborError::UnexpectedType);
        }
        self.enter()?;
        Ok(MapReader {
            remaining: len,
            last_key: None,
            reader: self,
        })
    }

    fn enter(&mut self) -> Result<(), CborError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(CborError::DepthExceeded);
        }
        Ok(())
    }

    pub fn leave(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth -= 1;
    }
}

/// Map reader enforcing strictly increasing unsigned integer keys.
pub struct MapReader<'a, 'r> {
    pub reader: &'r mut Reader<'a>,
    remaining: u64,
    last_key: Option<u64>,
}

impl<'a, 'r> MapReader<'a, 'r> {
    /// Reads the next key, verifying order. Returns None when the map is done.
    pub fn next_key(&mut self) -> Result<Option<u64>, CborError> {
        if self.remaining == 0 {
            self.reader.leave();
            return Ok(None);
        }
        self.remaining -= 1;
        let key = self.reader.uint()?;
        if let Some(last) = self.last_key
            && key <= last
        {
            return Err(CborError::KeyOrder);
        }
        self.last_key = Some(key);
        Ok(Some(key))
    }

    /// Requires the next key to be exactly `key`.
    pub fn expect_key(&mut self, key: u64) -> Result<(), CborError> {
        match self.next_key()? {
            Some(k) if k == key => Ok(()),
            Some(_) => Err(CborError::MissingField(key)),
            None => Err(CborError::MissingField(key)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_form_roundtrip() {
        let mut w = Writer::new();
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            w.uint(v);
        }
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes).unwrap();
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            assert_eq!(r.uint().unwrap(), v);
        }
        r.finish().unwrap();
    }

    #[test]
    fn rejects_non_canonical_uint() {
        // 0x18 0x05 is uint 5 in two bytes: non-canonical.
        let mut r = Reader::new(&[0x18, 0x05]).unwrap();
        assert_eq!(r.uint(), Err(CborError::NonCanonical));
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x5f = indefinite-length byte string.
        let mut r = Reader::new(&[0x5f]).unwrap();
        assert_eq!(r.bytes(), Err(CborError::ForbiddenType));
    }

    #[test]
    fn rejects_bad_key_order() {
        let mut w = Writer::new();
        w.map(2);
        w.uint(1);
        w.uint(10);
        w.uint(1); // duplicate key
        w.uint(11);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes).unwrap();
        let mut m = r.map().unwrap();
        assert_eq!(m.next_key().unwrap(), Some(1));
        m.reader.uint().unwrap();
        assert_eq!(m.next_key(), Err(CborError::KeyOrder));
    }

    #[test]
    fn map_writer_emits_expected_bytes() {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 2);
        m.uint(0, 2);
        m.bytes(1, &[0xaa, 0xbb]);
        m.end();
        assert_eq!(
            w.into_bytes(),
            vec![0xa2, 0x00, 0x02, 0x01, 0x42, 0xaa, 0xbb]
        );
    }
}
