// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Native event queue (§25.3.1).
//!
//! No callbacks into Go from arbitrary Rust threads (§25.2), so the
//! application polls. Transfers push here, `rtp2_poll_event` pops.
//!
//! Three things hold, each pinned by a test: an event carries ids, counters
//! and error codes but never key material; the queue is bounded, so a slow
//! consumer loses events instead of stalling the transfer; and progress counts
//! only bytes that passed proof and AEAD checks.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use parking_lot::{Condvar, Mutex};

use crate::cbor::{MapWriter, Writer};

/// Bound on queued events (§25.3.1). Sized so losing a terminal event takes
/// hundreds of abandoned transfers and no polling at all.
pub const MAX_EVENTS: usize = 1024;

/// Which side measured a `TRANSFER_PROGRESS` (§25.3.1). The roles count
/// different things, so the event says which, rather than one field meaning
/// two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressRole {
    /// Bytes that passed proof and AEAD checks: on disk and trustworthy.
    Receiving = 0,
    /// Bytes handed to the transport. Not delivery: only
    /// `TransferCompleted` says the peer has the object.
    Sending = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    TransferStarted {
        transfer_id: [u8; 32],
        objects: u64,
        total_bytes: u64,
    },
    TransferProgress {
        transfer_id: [u8; 32],
        role: ProgressRole,
        bytes: u64,
        total_bytes: u64,
        chunks: u64,
        total_chunks: u64,
    },
    ObjectCompleted {
        transfer_id: [u8; 32],
        object_id: [u8; 32],
        plaintext_digest: [u8; 32],
    },
    TransferCompleted {
        transfer_id: [u8; 32],
        objects: u64,
    },
    TransferFailed {
        transfer_id: [u8; 32],
        code: u64,
    },
    TransferCancelled {
        transfer_id: [u8; 32],
    },
    EventsDropped {
        lost: u64,
    },
    /// The path this transfer is using (§16.3.1). `address_class` is `Some`
    /// exactly when the route is direct.
    TransferRoute {
        transfer_id: [u8; 32],
        route: u64,
        address_class: Option<u64>,
    },
}

impl Event {
    pub fn type_code(&self) -> u64 {
        match self {
            Event::TransferStarted { .. } => 1,
            Event::TransferProgress { .. } => 2,
            Event::ObjectCompleted { .. } => 3,
            Event::TransferCompleted { .. } => 4,
            Event::TransferFailed { .. } => 5,
            Event::TransferCancelled { .. } => 6,
            Event::EventsDropped { .. } => 7,
            Event::TransferRoute { .. } => 8,
        }
    }

    /// Types 3-6 end a transfer. Lose one and the application cannot tell
    /// whether it succeeded, so overflow never takes them first.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Event::ObjectCompleted { .. }
                | Event::TransferCompleted { .. }
                | Event::TransferFailed { .. }
                | Event::TransferCancelled { .. }
        )
    }

    /// Coalescing key. Progress collapses within one transfer and one role
    /// only: a loopback process runs both roles under one transfer id, and
    /// merging would mix "verified" with "transmitted".
    fn progress_key(&self) -> Option<([u8; 32], ProgressRole)> {
        match self {
            Event::TransferProgress {
                transfer_id, role, ..
            } => Some((*transfer_id, *role)),
            _ => None,
        }
    }

    /// Deterministic RTP-CBOR matching the `event` rule in `rtp2.cddl`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Event::TransferStarted {
                transfer_id,
                objects,
                total_bytes,
            } => {
                let mut m = MapWriter::begin(&mut w, 4);
                m.uint(0, 1);
                m.bytes(1, transfer_id);
                m.uint(2, *objects);
                m.uint(3, *total_bytes);
                m.end();
            }
            Event::TransferProgress {
                transfer_id,
                role,
                bytes,
                total_bytes,
                chunks,
                total_chunks,
            } => {
                let mut m = MapWriter::begin(&mut w, 7);
                m.uint(0, 2);
                m.bytes(1, transfer_id);
                m.uint(2, *bytes);
                m.uint(3, *total_bytes);
                m.uint(4, *chunks);
                m.uint(5, *total_chunks);
                m.uint(6, *role as u64);
                m.end();
            }
            Event::ObjectCompleted {
                transfer_id,
                object_id,
                plaintext_digest,
            } => {
                let mut m = MapWriter::begin(&mut w, 4);
                m.uint(0, 3);
                m.bytes(1, transfer_id);
                m.bytes(2, object_id);
                m.bytes(3, plaintext_digest);
                m.end();
            }
            Event::TransferCompleted {
                transfer_id,
                objects,
            } => {
                let mut m = MapWriter::begin(&mut w, 3);
                m.uint(0, 4);
                m.bytes(1, transfer_id);
                m.uint(2, *objects);
                m.end();
            }
            Event::TransferFailed { transfer_id, code } => {
                let mut m = MapWriter::begin(&mut w, 3);
                m.uint(0, 5);
                m.bytes(1, transfer_id);
                m.uint(2, *code);
                m.end();
            }
            Event::TransferCancelled { transfer_id } => {
                let mut m = MapWriter::begin(&mut w, 2);
                m.uint(0, 6);
                m.bytes(1, transfer_id);
                m.end();
            }
            Event::EventsDropped { lost } => {
                let mut m = MapWriter::begin(&mut w, 2);
                m.uint(0, 7);
                m.uint(1, *lost);
                m.end();
            }
            Event::TransferRoute {
                transfer_id,
                route,
                address_class,
            } => {
                // Key 3 only for a direct route, as the CDDL says. An
                // optional key always written is a different rule.
                let mut m = MapWriter::begin(&mut w, if address_class.is_some() { 4 } else { 3 });
                m.uint(0, 8);
                m.bytes(1, transfer_id);
                m.uint(2, *route);
                if let Some(class) = address_class {
                    m.uint(3, *class);
                }
                m.end();
            }
        }
        w.into_bytes()
    }
}

#[derive(Default)]
struct Inner {
    queue: VecDeque<Event>,
    /// Unreported drops. A counter, not a queued event, so the report can
    /// never itself be evicted by a later overflow.
    unreported_drops: u64,
}

impl Inner {
    /// Makes room for one event, preferring to lose a droppable one.
    fn evict_one(&mut self) {
        let victim = self.queue.iter().position(|e| !e.is_terminal());
        match victim {
            Some(index) => {
                self.queue.remove(index);
            }
            None => {
                // Only terminal events left. Bounding memory wins and the
                // loss is still reported (§25.3.1).
                self.queue.pop_front();
            }
        }
        self.unreported_drops = self.unreported_drops.saturating_add(1);
    }
}

/// One queue per runtime, so freeing a transfer handle cannot take its
/// terminal event with it (§25.3.1).
#[derive(Default)]
pub struct EventQueue {
    inner: Mutex<Inner>,
    signal: Condvar,
}

impl EventQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, event: Event) {
        let mut inner = self.inner.lock();

        // Collapse consecutive progress. Not a drop: counters are
        // cumulative, so the newer event says everything the older one did.
        if let Some(key) = event.progress_key()
            && inner.queue.back().and_then(Event::progress_key) == Some(key)
        {
            inner.queue.pop_back();
        }

        if inner.queue.len() >= MAX_EVENTS {
            inner.evict_one();
        }
        inner.queue.push_back(event);
        self.signal.notify_one();
    }

    /// Next event, waiting up to `timeout`; zero returns immediately. Drops
    /// come first, so an application hears about a hole before acting on what
    /// followed it.
    pub fn poll(&self, timeout: Duration) -> Option<Event> {
        let deadline = Instant::now().checked_add(timeout);
        let mut inner = self.inner.lock();
        loop {
            if inner.unreported_drops > 0 {
                let lost = std::mem::take(&mut inner.unreported_drops);
                return Some(Event::EventsDropped { lost });
            }
            if let Some(event) = inner.queue.pop_front() {
                return Some(event);
            }
            let deadline = deadline?;
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            self.signal.wait_for(&mut inner, deadline - now);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn progress(n: u8, bytes: u64) -> Event {
        progress_as(n, bytes, ProgressRole::Receiving)
    }

    fn progress_as(n: u8, bytes: u64, role: ProgressRole) -> Event {
        Event::TransferProgress {
            transfer_id: tid(n),
            role,
            bytes,
            total_bytes: 1000,
            chunks: bytes / 100,
            total_chunks: 10,
        }
    }

    #[test]
    fn events_arrive_in_order_for_one_transfer() {
        let q = EventQueue::new();
        q.push(Event::TransferStarted {
            transfer_id: tid(1),
            objects: 1,
            total_bytes: 1000,
        });
        q.push(progress(1, 500));
        q.push(Event::TransferCompleted {
            transfer_id: tid(1),
            objects: 1,
        });

        let types: Vec<u64> = (0..3)
            .map(|_| q.poll(Duration::ZERO).unwrap().type_code())
            .collect();
        assert_eq!(types, vec![1, 2, 4]);
        assert!(q.poll(Duration::ZERO).is_none());
    }

    #[test]
    fn consecutive_progress_is_coalesced_but_never_counted_as_a_drop() {
        let q = EventQueue::new();
        for bytes in [100, 200, 300, 400] {
            q.push(progress(1, bytes));
        }
        assert_eq!(q.len(), 1, "consecutive progress collapses");

        // The newest survives, and since counters are cumulative nothing was
        // lost, so no EVENTS_DROPPED.
        match q.poll(Duration::ZERO).unwrap() {
            Event::TransferProgress { bytes, .. } => assert_eq!(bytes, 400),
            other => panic!("expected progress, got {other:?}"),
        }
        assert!(
            q.poll(Duration::ZERO).is_none(),
            "coalescing must not be reported as a drop"
        );
    }

    #[test]
    fn progress_for_a_different_role_does_not_coalesce() {
        // Loopback is both sender and receiver under one transfer id.
        // Merging would mix "verified" with "merely transmitted".
        let q = EventQueue::new();
        q.push(progress_as(1, 100, ProgressRole::Receiving));
        q.push(progress_as(1, 900, ProgressRole::Sending));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn progress_for_a_different_transfer_does_not_coalesce() {
        // Coalescing across transfers would lose one transfer's progress
        // entirely whenever two run at once.
        let q = EventQueue::new();
        q.push(progress(1, 100));
        q.push(progress(2, 100));
        q.push(progress(1, 200));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn overflow_drops_progress_and_keeps_terminal_events() {
        let q = EventQueue::new();
        // One terminal event first, then enough progress from distinct
        // transfers to overflow the bound without coalescing.
        q.push(Event::TransferCompleted {
            transfer_id: tid(0),
            objects: 1,
        });
        for i in 0..MAX_EVENTS + 50 {
            q.push(progress((i % 200 + 1) as u8, i as u64));
        }
        assert!(q.len() <= MAX_EVENTS, "the queue must stay bounded");

        // The drop report comes first...
        match q.poll(Duration::ZERO).unwrap() {
            Event::EventsDropped { lost } => assert!(lost > 0, "drops must be counted"),
            other => panic!("expected a drop report first, got {other:?}"),
        }
        // ...and the terminal event survived the flood.
        assert_eq!(
            q.poll(Duration::ZERO).unwrap().type_code(),
            4,
            "a terminal event must not be evicted while progress can be"
        );
    }

    #[test]
    fn the_drop_report_cannot_itself_be_dropped() {
        let q = EventQueue::new();
        for i in 0..MAX_EVENTS * 3 {
            q.push(progress((i % 200 + 1) as u8, i as u64));
        }
        // However long the flood ran, the next poll says how much was lost.
        // A counter cannot be evicted, which is why it is one.
        assert!(matches!(
            q.poll(Duration::ZERO),
            Some(Event::EventsDropped { .. })
        ));
    }

    #[test]
    fn a_zero_timeout_returns_immediately_and_a_wait_is_bounded() {
        let q = EventQueue::new();
        assert!(q.poll(Duration::ZERO).is_none());

        let start = Instant::now();
        assert!(q.poll(Duration::from_millis(60)).is_none());
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(40), "waited {waited:?}");
        assert!(waited < Duration::from_secs(5), "waited {waited:?}");
    }

    #[test]
    fn a_waiting_poll_wakes_on_a_push() {
        let q = std::sync::Arc::new(EventQueue::new());
        let writer = std::sync::Arc::clone(&q);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            writer.push(Event::TransferCancelled {
                transfer_id: tid(9),
            });
        });
        let event = q
            .poll(Duration::from_secs(5))
            .expect("a push must wake a waiting poll");
        assert_eq!(event.type_code(), 6);
    }

    #[test]
    fn events_carry_no_secrets() {
        // Over the encoded bytes, not the type, so a future field added to
        // the encoder has to pass this too.
        let secret = [0xAB; 32];
        let events = vec![
            Event::TransferStarted {
                transfer_id: tid(1),
                objects: 1,
                total_bytes: 64,
            },
            progress(1, 32),
            Event::ObjectCompleted {
                transfer_id: tid(1),
                object_id: tid(2),
                plaintext_digest: tid(3),
            },
            Event::TransferCompleted {
                transfer_id: tid(1),
                objects: 1,
            },
            Event::TransferFailed {
                transfer_id: tid(1),
                code: 0x0006,
            },
            Event::TransferCancelled {
                transfer_id: tid(1),
            },
            Event::EventsDropped { lost: 3 },
            Event::TransferRoute {
                transfer_id: tid(1),
                route: 0,
                address_class: Some(1),
            },
        ];
        for event in &events {
            let encoded = event.encode();
            assert!(
                !encoded.windows(32).any(|w| w == secret),
                "{event:?} leaked key-shaped material"
            );
            // Events are small. Anything file-sized means plaintext or a
            // path slipped in.
            assert!(
                encoded.len() < 128,
                "{event:?} encodes to {} bytes",
                encoded.len()
            );
        }
    }

    /// Decodes an event exactly as the CDDL describes and checks every field.
    /// Field by field on purpose: this is the check that encoder and schema
    /// agree, so it has to look at what was written.
    fn assert_matches_cddl(event: &Event) {
        use crate::cbor::Reader;
        let encoded = event.encode();
        let mut r = Reader::new(&encoded).expect("decodable by the §13.4 decoder");
        let mut m = r.map().expect("a map");
        m.expect_key(0).expect("type is key 0");
        assert_eq!(m.reader.uint().expect("type code"), event.type_code());

        match event {
            Event::TransferStarted {
                transfer_id,
                objects,
                total_bytes,
            } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *objects);
                m.expect_key(3).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *total_bytes);
            }
            Event::TransferProgress {
                transfer_id,
                role,
                bytes,
                total_bytes,
                chunks,
                total_chunks,
            } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *bytes);
                m.expect_key(3).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *total_bytes);
                m.expect_key(4).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *chunks);
                m.expect_key(5).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *total_chunks);
                m.expect_key(6).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *role as u64);
            }
            Event::ObjectCompleted {
                transfer_id,
                object_id,
                plaintext_digest,
            } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), object_id);
                m.expect_key(3).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), plaintext_digest);
            }
            Event::TransferCompleted {
                transfer_id,
                objects,
            } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *objects);
            }
            Event::TransferFailed { transfer_id, code } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *code);
            }
            Event::TransferCancelled { transfer_id } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
            }
            Event::EventsDropped { lost } => {
                m.expect_key(1).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *lost);
            }
            Event::TransferRoute {
                transfer_id,
                route,
                address_class,
            } => {
                m.expect_key(1).unwrap();
                assert_eq!(&m.reader.bytes_exact::<32>().unwrap(), transfer_id);
                m.expect_key(2).unwrap();
                assert_eq!(m.reader.uint().unwrap(), *route);
                // Key 3 is optional and present exactly for a direct route.
                if let Some(class) = address_class {
                    m.expect_key(3).unwrap();
                    assert_eq!(m.reader.uint().unwrap(), *class);
                }
            }
        }

        assert!(
            m.next_key().expect("well-formed").is_none(),
            "no field beyond the CDDL rule"
        );
        r.finish().expect("no trailing bytes");
    }

    #[test]
    fn every_event_type_matches_its_cddl_rule() {
        for event in [
            Event::TransferStarted {
                transfer_id: tid(1),
                objects: 2,
                total_bytes: 3,
            },
            progress(1, 400),
            Event::ObjectCompleted {
                transfer_id: tid(1),
                object_id: tid(2),
                plaintext_digest: tid(3),
            },
            Event::TransferCompleted {
                transfer_id: tid(1),
                objects: 5,
            },
            Event::TransferFailed {
                transfer_id: tid(1),
                code: 6,
            },
            Event::TransferCancelled {
                transfer_id: tid(1),
            },
            Event::EventsDropped { lost: 7 },
            Event::TransferRoute {
                transfer_id: tid(1),
                route: 0,
                address_class: Some(0),
            },
            Event::TransferRoute {
                transfer_id: tid(1),
                route: 1,
                address_class: None,
            },
            Event::TransferRoute {
                transfer_id: tid(1),
                route: 2,
                address_class: None,
            },
        ] {
            assert_matches_cddl(&event);
        }
    }
}
