// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Range scheduler (§18.1–§18.2, §19.2–§19.4).
//!
//! Decides what to ask for next and how much concurrency to use. No I/O of
//! its own: bitmap plus observed link quality in, valid range requests out.

use crate::{
    bitmap::{ChunkBitmap, MAX_RANGES_PER_REQUEST},
    cbor::{CborError, MapWriter, Reader, Writer},
};

/// §19.3 priority classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    CriticalMetadata = 0,
    FirstRender = 1,
    UserVisibleNext = 2,
    Sequential = 3,
    Background = 4,
    Repair = 5,
}

impl Priority {
    pub fn from_u64(v: u64) -> Option<Self> {
        Some(match v {
            0 => Priority::CriticalMetadata,
            1 => Priority::FirstRender,
            2 => Priority::UserVisibleNext,
            3 => Priority::Sequential,
            4 => Priority::Background,
            5 => Priority::Repair,
            _ => return None,
        })
    }
}

/// §18.1 preferred_chunk_order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOrder {
    /// Ascending: best for sequential media and storage locality.
    Sequential = 0,
    /// Rarest-first style ordering, for multi-source fan-out.
    Scattered = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    Encoding,
    TooManyRanges,
    UnsortedOrOverlapping,
    EmptyRange,
    OutOfRange,
}

impl From<CborError> for SchedulerError {
    fn from(_: CborError) -> Self {
        SchedulerError::Encoding
    }
}

// ---------------------------------------------------------------------------
// Range request (§18.1), `range-request` in rtp2.cddl
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRequest {
    pub transfer_id: [u8; 32],
    pub object_id: [u8; 32],
    pub priority_class: u64,
    /// Chunk-index ranges `[start, end)`.
    pub ranges: Vec<(u64, u64)>,
    pub max_bytes: u64,
    pub preferred_chunk_order: u64,
    pub durable_ack_generation: u64,
}

impl RangeRequest {
    /// §18.2: at most 1024 ranges, sorted, disjoint, non-empty, inside the
    /// object. Checked on encode and decode, so neither side can be handed an
    /// invalid set. An empty list is valid and means nothing is needed.
    pub fn validate(&self, chunk_count: u64) -> Result<(), SchedulerError> {
        if self.ranges.len() > MAX_RANGES_PER_REQUEST {
            return Err(SchedulerError::TooManyRanges);
        }
        let mut previous_end = 0u64;
        for (i, &(start, end)) in self.ranges.iter().enumerate() {
            if end <= start {
                return Err(SchedulerError::EmptyRange);
            }
            if end > chunk_count {
                return Err(SchedulerError::OutOfRange);
            }
            // Each range starts past the previous one's end. Touching ranges
            // would have been merged, so they are rejected.
            if i > 0 && start <= previous_end {
                return Err(SchedulerError::UnsortedOrOverlapping);
            }
            previous_end = end;
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut m = MapWriter::begin(&mut w, 7);
        m.bytes(0, &self.transfer_id);
        m.bytes(1, &self.object_id);
        m.uint(2, self.priority_class);
        {
            let inner = m.nested(3);
            inner.array(self.ranges.len() as u64);
            for (start, end) in &self.ranges {
                inner.array(2);
                inner.uint(*start);
                inner.uint(*end);
            }
        }
        m.uint(4, self.max_bytes);
        m.uint(5, self.preferred_chunk_order);
        m.uint(6, self.durable_ack_generation);
        m.end();
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8], chunk_count: u64) -> Result<Self, SchedulerError> {
        let mut r = Reader::new(bytes)?;
        let mut m = r.map()?;
        m.expect_key(0)?;
        let transfer_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(1)?;
        let object_id = m.reader.bytes_exact::<32>()?;
        m.expect_key(2)?;
        let priority_class = m.reader.uint()?;
        m.expect_key(3)?;
        let count = m.reader.array()?;
        if count as usize > MAX_RANGES_PER_REQUEST {
            return Err(SchedulerError::TooManyRanges);
        }
        let mut ranges = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if m.reader.array()? != 2 {
                return Err(SchedulerError::Encoding);
            }
            let start = m.reader.uint()?;
            let end = m.reader.uint()?;
            m.reader.leave();
            ranges.push((start, end));
        }
        m.reader.leave();
        m.expect_key(4)?;
        let max_bytes = m.reader.uint()?;
        m.expect_key(5)?;
        let preferred_chunk_order = m.reader.uint()?;
        m.expect_key(6)?;
        let durable_ack_generation = m.reader.uint()?;
        if m.next_key()?.is_some() {
            return Err(SchedulerError::Encoding);
        }
        r.finish()?;

        let request = Self {
            transfer_id,
            object_id,
            priority_class,
            ranges,
            max_bytes,
            preferred_chunk_order,
            durable_ack_generation,
        };
        request.validate(chunk_count)?;
        Ok(request)
    }

    /// Total chunks named by the request.
    pub fn chunk_total(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }
}

// ---------------------------------------------------------------------------
// Network quality and concurrency (§19.2)
// ---------------------------------------------------------------------------

/// What the transport last observed. The scheduler reads it and measures
/// nothing itself.
#[derive(Debug, Clone, Copy)]
pub struct NetworkQuality {
    pub rtt_ms: u32,
    pub rtt_variance_ms: u32,
    pub loss_permille: u32,
    pub storage_is_bottleneck: bool,
    pub thermal_pressure: bool,
}

impl Default for NetworkQuality {
    fn default() -> Self {
        Self {
            rtt_ms: 80,
            rtt_variance_ms: 10,
            loss_permille: 0,
            storage_is_bottleneck: false,
            thermal_pressure: false,
        }
    }
}

/// §19.2 concurrency table, plus the reduction rules below it.
pub fn recommended_streams(quality: &NetworkQuality) -> u32 {
    // Base tier from RTT and loss, matching the table's rows.
    let mut streams: u32 = if quality.loss_permille >= 20 || quality.rtt_ms >= 400 {
        1
    } else if quality.rtt_ms >= 150 {
        2
    } else if quality.rtt_ms >= 40 {
        4
    } else {
        8
    };

    // Reduce on rising variance, thermal pressure, or storage saturation.
    if quality.rtt_variance_ms * 2 >= quality.rtt_ms.max(1) {
        streams = streams.div_ceil(2);
    }
    if quality.thermal_pressure {
        streams = streams.div_ceil(2);
    }
    if quality.storage_is_bottleneck {
        streams = streams.div_ceil(2);
    }
    streams.max(1)
}

/// Recommended plaintext chunk size for the link (§10.2). Advisory only: the
/// size is fixed once an object exists, so this is for the sender.
pub fn recommended_chunk_size(quality: &NetworkQuality) -> u32 {
    if quality.loss_permille >= 20 || quality.rtt_ms >= 400 {
        64 * 1024
    } else if quality.rtt_ms >= 150 {
        256 * 1024
    } else if quality.rtt_ms >= 40 {
        1024 * 1024
    } else {
        4 * 1024 * 1024
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// A region of the object the application wants early, with its priority
/// (§19.3, §19.4). Ranges are chunk indices `[start, end)`.
#[derive(Debug, Clone)]
pub struct InterestRegion {
    pub priority: Priority,
    pub range: (u64, u64),
}

pub struct Scheduler {
    transfer_id: [u8; 32],
    object_id: [u8; 32],
    chunk_count: u64,
    chunk_ciphertext_size: u64,
    interests: Vec<InterestRegion>,
    order: ChunkOrder,
    generation: u64,
}

impl Scheduler {
    pub fn new(
        transfer_id: [u8; 32],
        object_id: [u8; 32],
        chunk_count: u64,
        chunk_ciphertext_size: u64,
    ) -> Self {
        Self {
            transfer_id,
            object_id,
            chunk_count,
            chunk_ciphertext_size,
            interests: Vec::new(),
            order: ChunkOrder::Sequential,
            generation: 0,
        }
    }

    /// Registers the ranges that make an object useful before it is whole:
    /// format index, preview, first render (§19.4).
    pub fn add_interest(&mut self, priority: Priority, range: (u64, u64)) {
        if range.1 > range.0 {
            self.interests.push(InterestRegion { priority, range });
            self.interests.sort_by_key(|i| (i.priority, i.range.0));
        }
    }

    pub fn set_order(&mut self, order: ChunkOrder) {
        self.order = order;
    }

    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Next request from what is missing. Highest-priority unsatisfied
    /// interest wins; once all are satisfied the rest goes out as
    /// `Sequential`. `None` when nothing is missing.
    pub fn next_request(
        &self,
        have: &ChunkBitmap,
        quality: &NetworkQuality,
    ) -> Option<RangeRequest> {
        let missing = have.missing_ranges(MAX_RANGES_PER_REQUEST);
        if missing.is_empty() {
            return None;
        }

        // Work on the first interest that still has gaps.
        let (priority, candidate) = self
            .interests
            .iter()
            .find_map(|interest| {
                let clipped = intersect(&missing, interest.range);
                if clipped.is_empty() {
                    None
                } else {
                    Some((interest.priority, clipped))
                }
            })
            .unwrap_or((Priority::Sequential, missing));

        // Keep a request to a few round trips, so reprioritizing stays
        // responsive.
        let streams = recommended_streams(quality) as u64;
        let max_bytes = (self.chunk_ciphertext_size * 8 * streams).max(self.chunk_ciphertext_size);
        let max_chunks = (max_bytes / self.chunk_ciphertext_size.max(1)).max(1);

        let ranges = match self.order {
            ChunkOrder::Sequential => take_chunks(&candidate, max_chunks),
            ChunkOrder::Scattered => take_scattered(&candidate, max_chunks),
        };
        if ranges.is_empty() {
            return None;
        }

        Some(RangeRequest {
            transfer_id: self.transfer_id,
            object_id: self.object_id,
            priority_class: priority as u64,
            ranges,
            max_bytes,
            preferred_chunk_order: self.order as u64,
            durable_ack_generation: self.generation,
        })
    }

    /// Everything missing in one request, for a route switch where the new
    /// provider needs the whole picture (§18.5).
    ///
    /// A request with no ranges is a real answer, not an absent one: it is
    /// what an object that is already complete asks for, and it is valid on
    /// the wire. Returning `None` for that case made the one caller invent an
    /// empty request by hand, magic priority class and all, which is the
    /// scheduler's own encoding written out a second time by someone else.
    pub fn full_request(&self, have: &ChunkBitmap) -> RangeRequest {
        let ranges = have.missing_ranges(MAX_RANGES_PER_REQUEST);
        let total: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        RangeRequest {
            transfer_id: self.transfer_id,
            object_id: self.object_id,
            priority_class: Priority::Sequential as u64,
            ranges,
            max_bytes: total.saturating_mul(self.chunk_ciphertext_size),
            preferred_chunk_order: self.order as u64,
            durable_ack_generation: self.generation,
        }
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
}

/// Intersects a sorted, disjoint range list with one window.
fn intersect(ranges: &[(u64, u64)], window: (u64, u64)) -> Vec<(u64, u64)> {
    ranges
        .iter()
        .filter_map(|&(start, end)| {
            let s = start.max(window.0);
            let e = end.min(window.1);
            if s < e { Some((s, e)) } else { None }
        })
        .collect()
}

/// Takes at most `max_chunks` chunks from the front, preserving order.
fn take_chunks(ranges: &[(u64, u64)], max_chunks: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut budget = max_chunks;
    for &(start, end) in ranges {
        if budget == 0 {
            break;
        }
        let span = end - start;
        if span <= budget {
            out.push((start, end));
            budget -= span;
        } else {
            out.push((start, start + budget));
            budget = 0;
        }
    }
    out
}

/// Spreads chunks across the missing set, so several sources do not collide.
fn take_scattered(ranges: &[(u64, u64)], max_chunks: u64) -> Vec<(u64, u64)> {
    if ranges.is_empty() || max_chunks == 0 {
        return Vec::new();
    }
    // A slice off the front of each range, round-robin, until the budget is
    // spent. Prefixes keep the result sorted and disjoint.
    let mut out: Vec<(u64, u64)> = Vec::new();
    let per_range = (max_chunks / ranges.len() as u64).max(1);
    let mut budget = max_chunks;
    for &(start, end) in ranges {
        if budget == 0 {
            break;
        }
        let span = (end - start).min(per_range).min(budget);
        out.push((start, start + span));
        budget -= span;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK_CT: u64 = 256 * 1024 + 16;

    fn scheduler(chunk_count: u64) -> Scheduler {
        Scheduler::new([1; 32], [2; 32], chunk_count, CHUNK_CT)
    }

    #[test]
    fn requests_only_what_is_missing() {
        let s = scheduler(10);
        let mut have = ChunkBitmap::new(10).unwrap();
        for i in [0u64, 1, 2] {
            have.set(i).unwrap();
        }
        let req = s.next_request(&have, &NetworkQuality::default()).unwrap();
        assert_eq!(req.ranges, vec![(3, 10)]);
        req.validate(10).unwrap();

        // Complete: nothing to ask for.
        let full = ChunkBitmap::from_bytes(8, &[0xff]).unwrap();
        let s8 = scheduler(8);
        assert!(s8.next_request(&full, &NetworkQuality::default()).is_none());
    }

    #[test]
    fn priority_regions_come_first() {
        let mut s = scheduler(100);
        // §19.4: format metadata early, then first render, then the rest.
        s.add_interest(Priority::CriticalMetadata, (90, 92));
        s.add_interest(Priority::FirstRender, (0, 4));

        let have = ChunkBitmap::new(100).unwrap();
        let req = s.next_request(&have, &NetworkQuality::default()).unwrap();
        assert_eq!(req.priority_class, Priority::CriticalMetadata as u64);
        assert_eq!(req.ranges, vec![(90, 92)]);

        // With metadata in, first render is next, not chunk 4 onwards.
        let mut have = ChunkBitmap::new(100).unwrap();
        have.set(90).unwrap();
        have.set(91).unwrap();
        let req = s.next_request(&have, &NetworkQuality::default()).unwrap();
        assert_eq!(req.priority_class, Priority::FirstRender as u64);
        assert_eq!(req.ranges, vec![(0, 4)]);

        // Both satisfied: fall through to sequential over the remainder.
        for i in 0..4u64 {
            have.set(i).unwrap();
        }
        let req = s.next_request(&have, &NetworkQuality::default()).unwrap();
        assert_eq!(req.priority_class, Priority::Sequential as u64);
        assert_eq!(req.ranges[0].0, 4);
    }

    #[test]
    fn requests_respect_section_18_2() {
        // 4000 alternating gaps would exceed the 1024-range cap.
        let mut have = ChunkBitmap::new(8000).unwrap();
        for i in (0..8000).step_by(2) {
            have.set(i).unwrap();
        }
        let s = scheduler(8000);
        let req = s.full_request(&have);
        assert!(req.ranges.len() <= MAX_RANGES_PER_REQUEST);
        req.validate(8000).unwrap();

        // Sorted, disjoint, non-touching.
        for pair in req.ranges.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
            assert!(pair[0].0 < pair[0].1);
        }
    }

    #[test]
    fn validation_rejects_malformed_sets() {
        let base = RangeRequest {
            transfer_id: [1; 32],
            object_id: [2; 32],
            priority_class: 3,
            ranges: vec![(0, 2)],
            max_bytes: 1 << 20,
            preferred_chunk_order: 0,
            durable_ack_generation: 0,
        };
        base.validate(10).unwrap();

        // An empty list is valid: it means nothing is needed.
        let mut empty = base.clone();
        empty.ranges = vec![];
        empty.validate(10).unwrap();

        let mut inverted = base.clone();
        inverted.ranges = vec![(5, 5)];
        assert_eq!(inverted.validate(10), Err(SchedulerError::EmptyRange));

        let mut unsorted = base.clone();
        unsorted.ranges = vec![(4, 6), (0, 2)];
        assert_eq!(
            unsorted.validate(10),
            Err(SchedulerError::UnsortedOrOverlapping)
        );

        let mut overlapping = base.clone();
        overlapping.ranges = vec![(0, 5), (3, 7)];
        assert_eq!(
            overlapping.validate(10),
            Err(SchedulerError::UnsortedOrOverlapping)
        );

        let mut beyond = base.clone();
        beyond.ranges = vec![(0, 11)];
        assert_eq!(beyond.validate(10), Err(SchedulerError::OutOfRange));

        let mut too_many = base.clone();
        too_many.ranges = (0..2000).map(|i| (i * 2, i * 2 + 1)).collect();
        assert_eq!(
            too_many.validate(100_000),
            Err(SchedulerError::TooManyRanges)
        );
    }

    #[test]
    fn wire_roundtrip_and_hostile_input() {
        let s = scheduler(50);
        let mut have = ChunkBitmap::new(50).unwrap();
        for i in [0u64, 1, 10, 11, 30] {
            have.set(i).unwrap();
        }
        let req = s.full_request(&have);
        let bytes = req.encode();
        assert_eq!(RangeRequest::decode(&bytes, 50).unwrap(), req);

        // A request naming chunks beyond the object is refused on decode.
        assert!(RangeRequest::decode(&bytes, 20).is_err());

        // Byte flips are refused, never accepted as a different valid set.
        for pos in (0..bytes.len()).step_by(3) {
            let mut bad = bytes.clone();
            bad[pos] ^= 0x01;
            if let Ok(decoded) = RangeRequest::decode(&bad, 50) {
                assert!(decoded.validate(50).is_ok());
            }
        }
        // Garbage.
        assert!(RangeRequest::decode(&[], 50).is_err());
        assert!(RangeRequest::decode(&[0xff; 20], 50).is_err());
    }

    #[test]
    fn concurrency_follows_section_19_2() {
        let lan = NetworkQuality {
            rtt_ms: 2,
            rtt_variance_ms: 0,
            ..Default::default()
        };
        let wifi = NetworkQuality {
            rtt_ms: 60,
            rtt_variance_ms: 5,
            ..Default::default()
        };
        let lte = NetworkQuality {
            rtt_ms: 200,
            rtt_variance_ms: 20,
            ..Default::default()
        };
        let bad_3g = NetworkQuality {
            rtt_ms: 600,
            rtt_variance_ms: 200,
            loss_permille: 50,
            ..Default::default()
        };

        assert_eq!(recommended_streams(&lan), 8);
        assert_eq!(recommended_streams(&wifi), 4);
        assert_eq!(recommended_streams(&lte), 2);
        assert_eq!(recommended_streams(&bad_3g), 1);

        // Reductions apply and never drop below one stream.
        let jittery = NetworkQuality {
            rtt_ms: 60,
            rtt_variance_ms: 40,
            ..Default::default()
        };
        assert_eq!(recommended_streams(&jittery), 2);

        let stressed = NetworkQuality {
            rtt_ms: 60,
            rtt_variance_ms: 40,
            thermal_pressure: true,
            storage_is_bottleneck: true,
            ..Default::default()
        };
        assert_eq!(recommended_streams(&stressed), 1);
    }

    #[test]
    fn chunk_size_advice_matches_section_10_2() {
        // The recommendation must stay inside the allowed set (§10.2).
        for quality in [
            NetworkQuality {
                rtt_ms: 600,
                loss_permille: 50,
                ..Default::default()
            },
            NetworkQuality {
                rtt_ms: 200,
                ..Default::default()
            },
            NetworkQuality {
                rtt_ms: 60,
                ..Default::default()
            },
            NetworkQuality {
                rtt_ms: 2,
                ..Default::default()
            },
        ] {
            let size = recommended_chunk_size(&quality);
            assert!(
                crate::object::ALLOWED_CHUNK_SIZES.contains(&size),
                "{size} is not an allowed chunk size"
            );
        }
        // Worse links get smaller chunks, for resume granularity.
        let bad = NetworkQuality {
            rtt_ms: 600,
            loss_permille: 50,
            ..Default::default()
        };
        let good = NetworkQuality {
            rtt_ms: 2,
            ..Default::default()
        };
        assert!(recommended_chunk_size(&bad) < recommended_chunk_size(&good));
    }

    #[test]
    fn scattered_order_spreads_across_gaps() {
        let mut s = scheduler(1000);
        s.set_order(ChunkOrder::Scattered);
        let mut have = ChunkBitmap::new(1000).unwrap();
        // Three widely separated gaps.
        for i in 0..1000u64 {
            if !(0..100).contains(&i) && !(400..500).contains(&i) && !(900..1000).contains(&i) {
                have.set(i).unwrap();
            }
        }
        let req = s.next_request(&have, &NetworkQuality::default()).unwrap();
        assert_eq!(req.ranges.len(), 3, "one slice per gap");
        assert_eq!(req.preferred_chunk_order, ChunkOrder::Scattered as u64);
        req.validate(1000).unwrap();
    }
}
