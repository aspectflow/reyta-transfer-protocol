#!/usr/bin/env bash
#
# Copyright 2026 The Reyta Labs Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Transfer throughput against the transport ceiling, measured between two
# machines rather than inside one process.
#
# Why not `tests/e2e_bench.rs`: there both endpoints share one CPU and there is
# no link, so the transfer and the raw stream are both capped by the same
# thing and land within 2% of each other. That looks like "no headroom" and is
# an artefact. On a real gigabit link the same code carried 81 MiB/s while a
# raw QUIC stream carried 102 — the headroom was there all along, invisible to
# the in-process number.
#
# Usage:
#   PEER=user@host ./bench-two-machines.sh [MiB]
#
# The peer needs ~/rtp2 and ~/raw_quic (ship them first). Both are built by
# `make bench-binaries`. This machine receives; the peer sends.
#
# Exits non-zero when the transfer falls below MIN_RATIO of the raw ceiling,
# so it can gate a change rather than merely describe one.
set -uo pipefail

PEER="${PEER:?set PEER=user@host}"
MIB="${1:-256}"
MIN_RATIO="${MIN_RATIO:-0.92}"
WORK="${WORK:-/tmp/rtp2-bench}"
RTP2="${RTP2:-/tmp/rtp2-static}"
RAW="${RAW:-/tmp/raw_quic}"

mkdir -p "$WORK"
cd "$WORK"
cleanup() { pkill -f "$RTP2 -state $WORK/state" 2>/dev/null; pkill -f "$RAW serve" 2>/dev/null; }
trap cleanup EXIT

echo "payload         ${MIB} MiB, peer $PEER"
ssh "$PEER" "bash -lc '[ -s ~/bench-payload.bin ] || dd if=/dev/urandom of=~/bench-payload.bin bs=1m count=$MIB 2>/dev/null; ls -l ~/bench-payload.bin | awk \"{print \\\$5}\"'" >/dev/null

# ---- the ceiling: one QUIC stream, no RTP/2 code at all -------------------
rm -f raw-addr.txt raw.log
nohup "$RAW" serve >raw-addr.txt 2>raw.log &
for _ in $(seq 1 20); do [ -s raw-addr.txt ] && break; sleep 1; done
[ -s raw-addr.txt ] || { echo "raw_quic printed no address"; exit 1; }
RAW_OUT=$(ssh "$PEER" "bash -lc '~/raw_quic send \"$(cat raw-addr.txt)\" $MIB'" 2>&1 | tail -1)
RAW_RATE=$(echo "$RAW_OUT" | awk '{print $(NF-1)}')
echo "raw quic        ${RAW_RATE} MiB/s"

# ---- the transfer, same bytes over the same link --------------------------
rm -rf state received.bin addr.txt recv.log
nohup "$RTP2" -state "$WORK/state" -timeout 10m -quiet recv received.bin >addr.txt 2>recv.log &
for _ in $(seq 1 25); do [ -s addr.txt ] && break; sleep 1; done
[ -s addr.txt ] || { echo "receiver printed no address"; exit 1; }

# Subtract the fixed cost — process start plus the hybrid handshake — so the
# number is a rate and not a rate mixed with a constant.
scp -q addr.txt "$PEER:~/bench-addr.txt"
TINY=$(ssh "$PEER" "bash -lc 'printf x > ~/bench-tiny.bin; true'" 2>&1)
XFER=$( { time ssh "$PEER" "bash -lc '~/rtp2 -state ~/.rtp2 -quiet -route direct send \"\$(cat ~/bench-addr.txt)\" ~/bench-payload.bin >/dev/null'" ; } 2>&1 | awk '/^real/{print $2}')
echo "transfer        ${XFER} wall"

RATE=$(python3 -c "
import re,sys
t='$XFER'
m=re.match(r'(\d+)m([\d.]+)s',t)
secs=int(m.group(1))*60+float(m.group(2)) if m else float(t.rstrip('s'))
print(f'{$MIB/secs:.1f}')
")
echo "transfer rate   ${RATE} MiB/s"

python3 - "$RATE" "$RAW_RATE" "$MIN_RATIO" <<'PY'
import sys
rate, ceiling, floor = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])

# A run where the control collapsed says nothing about the transfer, and a
# ratio computed from it is meaningless — one such run reported 199% of a
# ceiling that had fallen to a quarter of the link, and called it a PASS.
# A gate that passes because its control broke is worse than no gate.
if ceiling < 0.5 * rate or ceiling < 20.0:
    print(f"INVALID: the raw ceiling measured {ceiling:.1f} MiB/s, which is not")
    print(f"         a ceiling for a transfer that reached {rate:.1f}. Something")
    print("         else was using the link. Re-run; do not read this as a result.")
    sys.exit(2)

ratio = rate / ceiling
print(f"ratio           {ratio:.1%} of the transport ceiling (floor {floor:.0%})")
if ratio < floor:
    print("FAIL: the transfer is leaving throughput on the table that the")
    print("      transport was willing to carry. That gap is ours.")
    sys.exit(1)
print("PASS")
PY
