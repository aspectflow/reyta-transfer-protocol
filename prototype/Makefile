RUST_CORE := native/rtp2-core

.PHONY: native cli example loop go-test rust-test throughput e2e-bench transport-bench mutation-check check clean

native:
	cd $(RUST_CORE) && cargo build --release

cli: native
	CGO_ENABLED=1 go build -o bin/rtp2 ./cmd/rtp2

go-test: native
	CGO_ENABLED=1 go test ./...

# The narrated end-to-end demonstration: two identities, one real QUIC link.
example: native
	CGO_ENABLED=1 go run ./examples/alice-bob $(FILE)

# Sends FILE to itself through the CLI and verifies the copy.
loop: native
	CGO_ENABLED=1 go run ./cmd/rtp2 -route loopback loop $(FILE) $(FILE).received

rust-test:
	cd $(RUST_CORE) && cargo test --release

# Where the time goes: per-stage crypto throughput, printed not asserted.
throughput:
	cd $(RUST_CORE) && cargo test --release --test throughput -- --nocapture --ignored

# Whole-transfer throughput. Pins the path to loopback and prints the network
# path beside it, because the two differ by ~48x and only one measures us.
e2e-bench:
	cd $(RUST_CORE) && cargo test --release --test e2e_bench -- --nocapture --ignored

# The control: one iroh stream, no RTP/2 code. Run this first when an
# end-to-end number looks wrong.
transport-bench:
	cd $(RUST_CORE) && cargo test --release --test raw_quic_bench -- --nocapture --ignored

mutation-check:
	cd $(RUST_CORE) && ./mutation-check.sh

check: go-test rust-test mutation-check

clean:
	cd $(RUST_CORE) && cargo clean
	rm -rf bin
