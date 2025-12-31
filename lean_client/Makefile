.PHONY: build format check-format test

all: build check-format test

build:
	cargo build --release

format:
	cargo fmt

check-format:
	cargo fmt --check

test:
	cargo test --workspace --all-features --no-fail-fast
