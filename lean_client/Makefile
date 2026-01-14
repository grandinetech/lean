all: build check-format test

.PHONY: format
format:
	cargo fmt

.PHONY: check-format
check-format:
	cargo fmt --check

.PHONY: test
test:
	cargo test --workspace --all-features --no-fail-fast

.PHONY: build
build:
	cargo build --release

.PHONY: x86_64-unknown-linux-gnu
x86_64-unknown-linux-gnu: ./target/x86_64-unknown-linux-gnu/release/lean_client

./target/x86_64-unknown-linux-gnu/release/lean_client:
	cross build --bin lean_client --target x86_64-unknown-linux-gnu --profile release

.PHONY: aarch64-unknown-linux-gnu
aarch64-unknown-linux-gnu: ./target/aarch64-unknown-linux-gnu/release/lean_client

./target/aarch64-unknown-linux-gnu/release/lean_client:
	cross build --bin lean_client --target aarch64-unknown-linux-gnu --profile release

DOCKER_REPO ?= sifrai/lean
DOCKER_TAG ?= unstable
COMMIT_SHA := $(shell git rev-parse HEAD)
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

.PHONY: release
release: docker

.PHONY: docker
docker: ./target/x86_64-unknown-linux-gnu/release/lean_client ./target/aarch64-unknown-linux-gnu/release/lean_client
	@mkdir -p ./bin/amd64
	@cp ./target/x86_64-unknown-linux-gnu/release/lean_client ./bin/amd64/lean_client
	@mkdir -p ./bin/arm64
	@cp ./target/aarch64-unknown-linux-gnu/release/lean_client ./bin/arm64/lean_client
	docker buildx build \
		--file Dockerfile \
		--platform linux/amd64,linux/arm64 \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(DOCKER_REPO):$(DOCKER_TAG) \
		--push \
		.
