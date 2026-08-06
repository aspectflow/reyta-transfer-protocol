// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Chunk bitmaps and their wire encoding (§18.3, §18.3.1).
//!
//! Bit `i` is chunk `i`, MSB first: byte `i / 8`, bit `7 - (i % 8)`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapError {
    IndexOutOfRange,
    TrailingBitsSet,
    WrongLength,
    RunOverflow,
    Truncated,
    TooLarge,
}

/// §18.2: a request carries at most this many ranges.
pub const MAX_RANGES_PER_REQUEST: usize = 1024;

/// Cap on `chunk_count`, so a hostile bitmap cannot ask for a huge
/// allocation. Far beyond any real object.
pub const MAX_CHUNK_COUNT: u64 = 1 << 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkBitmap {
    chunk_count: u64,
    bits: Vec<u8>,
    set_count: u64,
}

impl ChunkBitmap {
    pub fn new(chunk_count: u64) -> Result<Self, BitmapError> {
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(BitmapError::TooLarge);
        }
        Ok(Self {
            chunk_count,
            bits: vec![0u8; byte_len(chunk_count)],
            set_count: 0,
        })
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub fn set_count(&self) -> u64 {
        self.set_count
    }

    pub fn is_complete(&self) -> bool {
        self.set_count == self.chunk_count
    }

    pub fn get(&self, index: u64) -> Result<bool, BitmapError> {
        if index >= self.chunk_count {
            return Err(BitmapError::IndexOutOfRange);
        }
        let byte = self.bits[(index / 8) as usize];
        Ok(byte & (0x80 >> (index % 8)) != 0)
    }

    /// Sets a bit. Returns true if this call changed it.
    pub fn set(&mut self, index: u64) -> Result<bool, BitmapError> {
        if index >= self.chunk_count {
            return Err(BitmapError::IndexOutOfRange);
        }
        let mask = 0x80 >> (index % 8);
        let byte = &mut self.bits[(index / 8) as usize];
        if *byte & mask != 0 {
            return Ok(false);
        }
        *byte |= mask;
        self.set_count += 1;
        Ok(true)
    }

    /// Raw packed bytes, as stored and as fed to the RLE encoder.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Rebuilds from raw bytes. Trailing bits past `chunk_count` must be
    /// zero (§18.3.1).
    pub fn from_bytes(chunk_count: u64, bits: &[u8]) -> Result<Self, BitmapError> {
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(BitmapError::TooLarge);
        }
        if bits.len() != byte_len(chunk_count) {
            return Err(BitmapError::WrongLength);
        }
        let used = (chunk_count % 8) as u32;
        if used != 0 {
            let last = *bits.last().expect("non-empty when chunk_count > 0");
            let trailing_mask = 0xffu8 >> used;
            if last & trailing_mask != 0 {
                return Err(BitmapError::TrailingBitsSet);
            }
        }
        let set_count = bits.iter().map(|b| b.count_ones() as u64).sum();
        Ok(Self {
            chunk_count,
            bits: bits.to_vec(),
            set_count,
        })
    }

    /// Missing ranges `[start, end)`, sorted and non-overlapping (§18.2).
    /// Stops at `max_ranges`; ask again once those are filled.
    pub fn missing_ranges(&self, max_ranges: usize) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        let mut index = 0u64;
        while index < self.chunk_count && ranges.len() < max_ranges {
            // Skip present chunks.
            while index < self.chunk_count && self.get(index).unwrap_or(false) {
                index += 1;
            }
            if index >= self.chunk_count {
                break;
            }
            let start = index;
            while index < self.chunk_count && !self.get(index).unwrap_or(false) {
                index += 1;
            }
            ranges.push((start, index));
        }
        ranges
    }

    /// §18.3.1 RLE: LEB128 run lengths alternating clear and set, starting
    /// clear. A leading zero-length run means the bitmap starts set.
    pub fn encode_rle(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0u64;
        let mut expect_set = false; // first run is CLEAR

        while index < self.chunk_count {
            let value = self.get(index).expect("index < chunk_count");
            if value != expect_set {
                // Emit a zero-length run to flip polarity.
                write_leb128(&mut out, 0);
                expect_set = !expect_set;
                continue;
            }
            let start = index;
            while index < self.chunk_count && self.get(index).expect("in range") == value {
                index += 1;
            }
            write_leb128(&mut out, index - start);
            expect_set = !expect_set;
        }
        out
    }

    /// §18.3.1 decoding. The run total MUST equal `chunk_count` exactly.
    pub fn decode_rle(chunk_count: u64, encoded: &[u8]) -> Result<Self, BitmapError> {
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(BitmapError::TooLarge);
        }
        let mut bitmap = Self::new(chunk_count)?;
        let mut pos = 0usize;
        let mut index = 0u64;
        let mut is_set = false; // first run is CLEAR

        while pos < encoded.len() {
            let run = read_leb128(encoded, &mut pos)?;
            // Bounded by chunk_count, so a hostile run cannot drive a long
            // loop or a big allocation.
            if run > chunk_count - index {
                return Err(BitmapError::RunOverflow);
            }
            if is_set {
                for i in index..index + run {
                    bitmap.set(i)?;
                }
            }
            index += run;
            is_set = !is_set;
        }
        if index != chunk_count {
            return Err(BitmapError::RunOverflow);
        }
        Ok(bitmap)
    }
}

fn byte_len(chunk_count: u64) -> usize {
    chunk_count.div_ceil(8) as usize
}

fn write_leb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_leb128(input: &[u8], pos: &mut usize) -> Result<u64, BitmapError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= input.len() {
            return Err(BitmapError::Truncated);
        }
        let byte = input[*pos];
        *pos += 1;
        if shift >= 64 {
            return Err(BitmapError::RunOverflow);
        }
        result |= ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or(BitmapError::RunOverflow)?;
        if byte & 0x80 == 0 {
            // Non-minimal: a continuation byte carrying zero would give two
            // encodings of the same value.
            if byte == 0 && shift != 0 {
                return Err(BitmapError::RunOverflow);
            }
            return Ok(result);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_count() {
        let mut b = ChunkBitmap::new(20).unwrap();
        assert_eq!(b.set_count(), 0);
        assert!(!b.is_complete());
        assert!(b.set(0).unwrap());
        assert!(!b.set(0).unwrap(), "second set is a no-op");
        assert!(b.set(19).unwrap());
        assert_eq!(b.set_count(), 2);
        assert!(b.get(0).unwrap());
        assert!(b.get(19).unwrap());
        assert!(!b.get(1).unwrap());
        assert_eq!(b.get(20), Err(BitmapError::IndexOutOfRange));
        assert_eq!(b.set(20), Err(BitmapError::IndexOutOfRange));
    }

    #[test]
    fn msb_first_packing() {
        // §18.3.1: chunk i is byte i/8, bit 7-(i%8).
        let mut b = ChunkBitmap::new(8).unwrap();
        b.set(0).unwrap();
        assert_eq!(b.as_bytes(), &[0x80]);
        let mut b = ChunkBitmap::new(8).unwrap();
        b.set(7).unwrap();
        assert_eq!(b.as_bytes(), &[0x01]);
        let mut b = ChunkBitmap::new(16).unwrap();
        b.set(8).unwrap();
        assert_eq!(b.as_bytes(), &[0x00, 0x80]);
    }

    #[test]
    fn trailing_bits_must_be_zero() {
        // 12 chunks fill 1.5 bytes; the low nibble of byte 1 is padding.
        assert!(ChunkBitmap::from_bytes(12, &[0xff, 0xf0]).is_ok());
        assert_eq!(
            ChunkBitmap::from_bytes(12, &[0xff, 0xf1]),
            Err(BitmapError::TrailingBitsSet)
        );
        assert_eq!(
            ChunkBitmap::from_bytes(12, &[0xff]),
            Err(BitmapError::WrongLength)
        );
    }

    #[test]
    fn missing_ranges_are_sorted_and_disjoint() {
        let mut b = ChunkBitmap::new(10).unwrap();
        for i in [0u64, 1, 5, 9] {
            b.set(i).unwrap();
        }
        assert_eq!(b.missing_ranges(100), vec![(2, 5), (6, 9)]);

        let full = ChunkBitmap::from_bytes(8, &[0xff]).unwrap();
        assert!(full.missing_ranges(100).is_empty());
        assert!(full.is_complete());

        let empty = ChunkBitmap::new(5).unwrap();
        assert_eq!(empty.missing_ranges(100), vec![(0, 5)]);

        // §18.2 cap is honored.
        let mut sparse = ChunkBitmap::new(100).unwrap();
        for i in (0..100).step_by(2) {
            sparse.set(i).unwrap();
        }
        assert_eq!(sparse.missing_ranges(3).len(), 3);
    }

    #[test]
    fn rle_roundtrip_for_many_shapes() {
        let shapes: Vec<(u64, Vec<u64>)> = vec![
            (1, vec![]),
            (1, vec![0]),
            (8, vec![0, 1, 2, 3, 4, 5, 6, 7]),
            (10, vec![0, 1, 5, 9]),
            (17, vec![16]),
            (100, (0..100).step_by(3).collect()),
            (1000, (0..1000).filter(|i| i % 7 == 0).collect()),
        ];
        for (count, set) in shapes {
            let mut b = ChunkBitmap::new(count).unwrap();
            for i in &set {
                b.set(*i).unwrap();
            }
            let encoded = b.encode_rle();
            let decoded = ChunkBitmap::decode_rle(count, &encoded).unwrap();
            assert_eq!(decoded, b, "count={count} set={set:?}");
        }
    }

    #[test]
    fn rle_starting_with_set_bits_uses_a_zero_run() {
        let mut b = ChunkBitmap::new(4).unwrap();
        for i in 0..4 {
            b.set(i).unwrap();
        }
        let encoded = b.encode_rle();
        assert_eq!(encoded, vec![0x00, 0x04], "leading zero-length CLEAR run");
        assert_eq!(ChunkBitmap::decode_rle(4, &encoded).unwrap(), b);
    }

    #[test]
    fn rle_rejects_bad_totals_and_overflow() {
        // Runs summing below chunk_count.
        assert_eq!(
            ChunkBitmap::decode_rle(10, &[0x05]),
            Err(BitmapError::RunOverflow)
        );
        // Runs summing above chunk_count.
        assert_eq!(
            ChunkBitmap::decode_rle(4, &[0x00, 0x0a]),
            Err(BitmapError::RunOverflow)
        );
        // Truncated LEB128.
        assert_eq!(
            ChunkBitmap::decode_rle(10, &[0x80]),
            Err(BitmapError::Truncated)
        );
        // Non-minimal LEB128 (0x80 0x00 encodes 0 in two bytes).
        assert_eq!(
            ChunkBitmap::decode_rle(10, &[0x80, 0x00]),
            Err(BitmapError::RunOverflow)
        );
        // A huge declared run cannot drive an allocation.
        assert_eq!(
            ChunkBitmap::decode_rle(4, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Err(BitmapError::RunOverflow)
        );
    }

    #[test]
    fn large_bitmap_is_compact() {
        // A nearly-done 100k-chunk transfer should compress to a few bytes.
        // That is the whole point of the encoding.
        let mut b = ChunkBitmap::new(100_000).unwrap();
        for i in 0..99_999 {
            b.set(i).unwrap();
        }
        let encoded = b.encode_rle();
        assert!(encoded.len() < 16, "encoded to {} bytes", encoded.len());
        assert_eq!(ChunkBitmap::decode_rle(100_000, &encoded).unwrap(), b);
    }
}
