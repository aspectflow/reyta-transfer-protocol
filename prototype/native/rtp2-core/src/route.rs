// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! Observed network path, and the policy that can refuse one (§16.3.1).
//!
//! [`Route`] carries the class of path, not an address or relay URL: naming
//! someone else's relay in an app-visible event adds an identifier for no
//! gain. A relay carries only ciphertext, so refusing one is a metadata
//! decision, and the application's to make.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// How long a path the policy refuses is given to become one it admits, when
/// the caller expresses no preference.
///
/// A connection to a peer behind NAT starts on a relay and upgrades to a
/// direct path once holepunching completes, which takes a moment. Ten seconds
/// is past the point where that either worked or did not on a local network,
/// and short enough that a genuinely relay-only path fails quickly.
///
/// It is only a default. Between two devices behind carrier NAT, ten seconds
/// was spent in full and the transfer was refused — which is why how long to
/// wait is the caller's to set, exactly like what to accept.
pub const DEFAULT_ROUTE_GRACE: Duration = Duration::from_secs(10);

/// How far the bytes travelled on a direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Never left the machine.
    Loopback = 0,
    /// Private or link-local address: the local network.
    Private = 1,
    /// A globally routable address.
    Public = 2,
    /// RFC 6598 shared address space (100.64.0.0/10): the carrier's network.
    /// Not the local network, and not globally routable either — a mobile
    /// connection behind carrier-grade NAT lands here, as does a peer reached
    /// over a tunnel that hands out addresses from this range.
    ///
    /// It has its own class because the alternatives both state something
    /// false. Calling it private claims the bytes stayed on the local network
    /// when they crossed the carrier's; calling it public claims an address
    /// that is globally routable when it is not, and that one hid a real
    /// result: a transfer over a VPN reported `direct/public`, so the report
    /// could not tell a tunnel from the open internet.
    Shared = 3,
}

impl AddressClass {
    pub fn of(ip: IpAddr) -> Self {
        // A dual-stack socket reports an IPv4 peer as `::ffff:127.0.0.1`, for
        // which `Ipv6Addr::is_loopback` is false. Canonicalize before
        // classifying or a loopback path reads as public.
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            other => other,
        };
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    AddressClass::Loopback
                } else if v4.is_private() || v4.is_link_local() {
                    AddressClass::Private
                } else if is_shared_address_space(v4) {
                    AddressClass::Shared
                } else {
                    AddressClass::Public
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    AddressClass::Loopback
                } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                    AddressClass::Private
                } else {
                    AddressClass::Public
                }
            }
        }
    }

    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// Whether `v4` falls in RFC 6598 shared address space, 100.64.0.0/10.
///
/// `Ipv4Addr::is_shared` says this in one call but is still unstable, and this
/// crate builds on stable Rust.
fn is_shared_address_space(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    a == 100 && (64..=127).contains(&b)
}

/// The path a transfer actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A direct path to the peer.
    Direct(AddressClass),
    /// Through a relay: ciphertext only, but it sees that two endpoints are
    /// talking and how much.
    Relay,
    /// Something this version does not classify. Kept separate from `Relay`
    /// and `Direct` so no policy decision rests on a guess.
    Unknown,
}

impl Route {
    /// Wire/ABI code (§25.3.1 event type 8).
    pub fn as_u64(self) -> u64 {
        match self {
            Route::Direct(_) => 0,
            Route::Relay => 1,
            Route::Unknown => 2,
        }
    }

    /// Address class for a direct route; `None` otherwise.
    pub fn address_class(self) -> Option<AddressClass> {
        match self {
            Route::Direct(class) => Some(class),
            _ => None,
        }
    }

    /// Classifies one transport address (§16.3.1). Separate from the
    /// live-connection path so the relay branch is testable offline.
    pub fn of_transport(addr: &iroh::TransportAddr) -> Self {
        match addr {
            iroh::TransportAddr::Ip(addr) => Route::from_socket_addr(*addr),
            iroh::TransportAddr::Relay(_) => Route::Relay,
            _ => Route::Unknown,
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Route::Direct(AddressClass::of(addr.ip()))
    }

    /// Short, stable label for logs and reports.
    pub fn describe(self) -> &'static str {
        match self {
            Route::Direct(AddressClass::Loopback) => "direct/loopback",
            Route::Direct(AddressClass::Private) => "direct/private",
            Route::Direct(AddressClass::Public) => "direct/public",
            Route::Direct(AddressClass::Shared) => "direct/shared",
            Route::Relay => "relay",
            Route::Unknown => "unknown",
        }
    }
}

/// What the application will accept (§16.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutePolicy {
    /// Any path. The route is still reported. Default, so no caller has a
    /// restriction imposed that it did not ask for.
    #[default]
    Any = 0,
    /// Refuse a relayed path. This is the enforcement `PRIVATE_RELAY` and
    /// `STEALTH_TRANSFER` need in order to mean anything.
    DirectOnly = 1,
    /// Refuse anything that leaves the machine.
    LoopbackOnly = 2,
}

impl RoutePolicy {
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(RoutePolicy::Any),
            1 => Some(RoutePolicy::DirectOnly),
            2 => Some(RoutePolicy::LoopbackOnly),
            _ => None,
        }
    }

    /// Whether `route` satisfies this policy. `Unknown` satisfies only `Any`:
    /// an unidentified path must not pass a policy meant to keep bytes off
    /// third-party infrastructure.
    pub fn admits(self, route: Route) -> bool {
        matches!(
            (self, route),
            (RoutePolicy::Any, _)
                | (RoutePolicy::DirectOnly, Route::Direct(_))
                | (
                    RoutePolicy::LoopbackOnly,
                    Route::Direct(AddressClass::Loopback)
                )
        )
    }

    /// Whether a peer should hear about `addr` at all. Advertising one that
    /// admission would refuse gives a transfer that connects and dies. Relays
    /// are never filtered: no address to classify, and direct paths are
    /// negotiated over them.
    pub fn advertises(self, addr: &iroh::TransportAddr) -> bool {
        matches!(addr, iroh::TransportAddr::Relay(_)) || self.admits(Route::of_transport(addr))
    }
}

/// What the application will accept, and how long it will wait to get it.
///
/// The two travel together because they are one decision. Demanding a direct
/// path without saying how long holepunching may take leaves the deadline to
/// whoever wrote the library, and that deadline is what decides whether the
/// demand can be met at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteAdmission {
    pub policy: RoutePolicy,
    pub grace: Duration,
}

impl Default for RouteAdmission {
    fn default() -> Self {
        Self {
            policy: RoutePolicy::default(),
            grace: DEFAULT_ROUTE_GRACE,
        }
    }
}

impl RouteAdmission {
    /// The default grace period with an explicit policy.
    pub fn new(policy: RoutePolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn with_grace(self, grace: Duration) -> Self {
        Self { grace, ..self }
    }
}

impl From<RoutePolicy> for RouteAdmission {
    fn from(policy: RoutePolicy) -> Self {
        Self::new(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_transport_address_class_is_classified() {
        use iroh::TransportAddr;
        use std::str::FromStr;

        // A relay reported as direct would let a direct-only policy pass
        // ciphertext through a node the application excluded.
        let relay = TransportAddr::Relay(
            iroh::RelayUrl::from_str("https://relay.example/").expect("a relay url"),
        );
        assert_eq!(Route::of_transport(&relay), Route::Relay);
        assert!(!RoutePolicy::DirectOnly.admits(Route::of_transport(&relay)));

        for (addr, want) in [
            ("127.0.0.1:1234", Route::Direct(AddressClass::Loopback)),
            ("10.33.0.2:1234", Route::Direct(AddressClass::Private)),
            ("8.8.8.8:1234", Route::Direct(AddressClass::Public)),
        ] {
            let ip = TransportAddr::Ip(addr.parse().unwrap());
            assert_eq!(Route::of_transport(&ip), want, "{addr}");
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn address_classes_match_their_ranges() {
        assert_eq!(AddressClass::of(ip("127.0.0.1")), AddressClass::Loopback);
        assert_eq!(AddressClass::of(ip("::1")), AddressClass::Loopback);
        assert_eq!(AddressClass::of(ip("10.33.0.2")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("172.18.1.143")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("192.168.1.5")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("169.254.1.1")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("fd00::1")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("fe80::1")), AddressClass::Private);
        assert_eq!(AddressClass::of(ip("8.8.8.8")), AddressClass::Public);
        assert_eq!(
            AddressClass::of(ip("2606:4700::1111")),
            AddressClass::Public
        );
    }

    #[test]
    fn shared_address_space_is_neither_private_nor_public() {
        // 100.64.0.0/10, the range the first real between-device test ran
        // over. Reported as public, it made a path through a tunnel
        // indistinguishable from one over the open internet.
        for addr in ["100.64.0.0", "100.65.252.2", "100.90.160.106", "100.127.255.255"] {
            assert_eq!(AddressClass::of(ip(addr)), AddressClass::Shared, "{addr}");
        }

        // The neighbours on either side of the range stay public: 100.63.x and
        // 100.128.x are ordinary routable space, and an off-by-one in the
        // second octet would swallow them.
        for addr in ["100.63.255.255", "100.128.0.0", "99.64.0.1", "101.64.0.1"] {
            assert_eq!(AddressClass::of(ip(addr)), AddressClass::Public, "{addr}");
        }

        // A dual-stack socket reports it mapped, like every other v4 address.
        assert_eq!(
            AddressClass::of(ip("::ffff:100.65.252.2")),
            AddressClass::Shared
        );

        // It is a direct path, so only the loopback policy refuses it.
        let route = Route::from_socket_addr("100.65.252.2:1234".parse().unwrap());
        assert!(RoutePolicy::DirectOnly.admits(route));
        assert!(!RoutePolicy::LoopbackOnly.admits(route));
    }

    #[test]
    fn ipv4_mapped_addresses_classify_as_their_ipv4_form() {
        // A dual-stack socket hands back `::ffff:a.b.c.d`, and no IPv6
        // predicate matches those, so without canonicalization they all read
        // Public. That made a loopback-bound endpoint report direct/public and
        // refuse its own path. The integration test found it, not review.
        assert_eq!(
            AddressClass::of(ip("::ffff:127.0.0.1")),
            AddressClass::Loopback
        );
        assert_eq!(
            AddressClass::of(ip("::ffff:10.33.0.2")),
            AddressClass::Private
        );
        assert_eq!(
            AddressClass::of(ip("::ffff:192.168.1.5")),
            AddressClass::Private
        );
        assert_eq!(AddressClass::of(ip("::ffff:8.8.8.8")), AddressClass::Public);

        // Genuine IPv6 is unaffected.
        assert_eq!(AddressClass::of(ip("::1")), AddressClass::Loopback);
        assert_eq!(AddressClass::of(ip("fd00::1")), AddressClass::Private);
    }

    #[test]
    fn the_two_addresses_that_started_this_are_not_loopback() {
        // The real address set of two endpoints in one process. Neither is
        // loopback, which is why 64 MiB took 12 seconds instead of a quarter
        // of one, quietly over a VPN.
        for addr in ["10.33.0.2:55240", "172.18.1.143:55240"] {
            let route = Route::from_socket_addr(addr.parse().unwrap());
            assert_eq!(route, Route::Direct(AddressClass::Private));
            assert!(!RoutePolicy::LoopbackOnly.admits(route));
            assert!(RoutePolicy::DirectOnly.admits(route));
        }
    }

    #[test]
    fn a_policy_refuses_a_relay_and_never_guesses() {
        assert!(RoutePolicy::Any.admits(Route::Relay));
        assert!(!RoutePolicy::DirectOnly.admits(Route::Relay));
        assert!(!RoutePolicy::LoopbackOnly.admits(Route::Relay));

        // Unclassified satisfies nothing but `Any`: a policy about keeping
        // bytes off other machines cannot be met by a path we cannot name.
        assert!(RoutePolicy::Any.admits(Route::Unknown));
        assert!(!RoutePolicy::DirectOnly.admits(Route::Unknown));
        assert!(!RoutePolicy::LoopbackOnly.admits(Route::Unknown));
    }

    #[test]
    fn loopback_only_is_strictly_stronger_than_direct_only() {
        let loopback = Route::Direct(AddressClass::Loopback);
        let private = Route::Direct(AddressClass::Private);
        let public = Route::Direct(AddressClass::Public);
        let shared = Route::Direct(AddressClass::Shared);

        for route in [loopback, private, public, shared] {
            assert!(RoutePolicy::DirectOnly.admits(route));
        }
        assert!(RoutePolicy::LoopbackOnly.admits(loopback));
        assert!(!RoutePolicy::LoopbackOnly.admits(private));
        assert!(!RoutePolicy::LoopbackOnly.admits(public));
        assert!(!RoutePolicy::LoopbackOnly.admits(shared));
    }

    #[test]
    fn descriptions_are_distinct() {
        // These end up in reports and logs, so two routes must never read
        // the same.
        let all = [
            Route::Direct(AddressClass::Loopback),
            Route::Direct(AddressClass::Private),
            Route::Direct(AddressClass::Public),
            Route::Direct(AddressClass::Shared),
            Route::Relay,
            Route::Unknown,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for route in all {
            assert!(
                seen.insert(route.describe()),
                "{route:?} duplicates a label"
            );
        }
    }
}
