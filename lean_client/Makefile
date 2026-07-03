### Variables

# Commit of lean specification. Allows to specify which spec version to use,
#   when generating test vectors.
LEAN_SPEC_COMMIT ?= f12000bd68a9640cffdfbd9a07503c9112d32bee
# Docker image name. Used for both release (with publish) and local builds.
DOCKER_REPO ?= sifrai/lean
# Image tag.
DOCKER_TAG ?= unstable
# Git commit hash of current source version. Used to include metadata into 
#   docker image.
COMMIT_SHA := $(shell git rev-parse HEAD)
# Git branch name, which was used to build current binary. Used to include 
#   metadata into docker image.
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
# Build date. Used for docker image metadata.
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
# Currently supported devnet. Used to publish devnet tag, along with `latest`.
CURRENT_DEVNET := devnet-5
# Repo root that cross bind-mounts into its build container (see
# `lean_client/Cross.toml`). Auto-derived locally; CI overrides via env.
LEAN_REPO_ROOT ?= $(shell git rev-parse --show-toplevel)

# Temporary variable, which constructs `--tag` arguments, to be passed into 
#   docker build command. It is used as intermediatery step, not as config 
#   option.
DOCKER_TAGS := --tag $(DOCKER_REPO):$(DOCKER_TAG)
ifeq ($(DOCKER_TAG),unstable)
    DOCKER_TAGS += --tag $(DOCKER_REPO):latest
	DOCKER_TAGS += --tag $(DOCKER_REPO):$(CURRENT_DEVNET)
endif

all: build check-format test

### Linting
## Format source code.
.PHONY: format
format:
	cargo fmt

## Check source code formatting. Issues can be automatically fixed with `make format`.
.PHONY: check-format
check-format:
	cargo fmt --check

.PHONY: test
test:
	cargo test --workspace --all-features --no-fail-fast --release

.PHONY: generate-test-vectors
generate-test-vectors:
	@rm -rf spec && \
		mkdir -p spec && \
		cd spec && \
		git init && \
		git remote add origin https://github.com/leanEthereum/leanSpec.git && \
		git fetch --depth 1 origin $(LEAN_SPEC_COMMIT) && \
		git switch --detach FETCH_HEAD
	# Pre-download prod keys. The pinned leanSpec commit predates leanSpec PR #745,
	# whose `download_keys` reads the still-open release URL. Remove once the pin
	# moves past PR #745.
	cd spec && \
		KEYS_URL=$$(uv run python -c "from consensus_testing.keys import KEY_DOWNLOAD_URLS; print(KEY_DOWNLOAD_URLS['prod'])") && \
		KEYS_DIR=packages/testing/src/consensus_testing/test_keys && \
		mkdir -p $$KEYS_DIR && \
		curl -sSL "$$KEYS_URL" -o /tmp/prod_scheme.tar.gz && \
		tar -xzf /tmp/prod_scheme.tar.gz -C $$KEYS_DIR
	cd spec && uv run fill --clean --fork=Lstar --scheme prod || echo "run failed"
	@for d in ./spec/fixtures/consensus/*/; do \
		f=$$(basename $$d); \
		rm -rf ./test_vectors/$$f/devnet ./test_vectors/$$f/lstar; \
		mkdir -p ./test_vectors/$$f/lstar; \
		cp -R $$d/lstar/. ./test_vectors/$$f/lstar/; \
	done

.PHONY: build
build:
	cargo build --release

.PHONY: clean
clean:
	cargo clean
	rm -rf ./bin

.PHONY: x86_64-unknown-linux-gnu
x86_64-unknown-linux-gnu: ./target/x86_64-unknown-linux-gnu/release/lean_client

./target/x86_64-unknown-linux-gnu/release/lean_client:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v3" \
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target x86_64-unknown-linux-gnu --profile release

.PHONY: aarch64-unknown-linux-gnu
aarch64-unknown-linux-gnu: ./target/aarch64-unknown-linux-gnu/release/lean_client

./target/aarch64-unknown-linux-gnu/release/lean_client:
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target aarch64-unknown-linux-gnu --profile release

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
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		$(DOCKER_TAGS) \
		--push \
		.

.PHONY: docker-local
docker-local: ./target/x86_64-unknown-linux-gnu/release/lean_client
	@mkdir -p ./bin/amd64
	@cp ./target/x86_64-unknown-linux-gnu/release/lean_client ./bin/amd64/lean_client
	docker build \
		--file Dockerfile \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		$(DOCKER_TAGS) \
		.

### Shadow-simulator support
# `rust/patch/quinn-udp` is a vendored fallback-only build of quinn-udp so QUIC
# runs under the Shadow simulator (which does not emulate sendmsg cmsg / GRO /
# GSO / ECN). Applied only for the shadow-* targets via cargo's --config
# override, so prod / devnet builds see the crates.io version.
SHADOW_CONFIG := --config 'patch.crates-io."quinn-udp".path="rust/patch/quinn-udp"'
SHADOW_FEATURES := --features shadow-integration

.PHONY: shadow-build
shadow-build:
	cargo build --profile shadow $(SHADOW_FEATURES) $(SHADOW_CONFIG)

.PHONY: shadow-x86_64-unknown-linux-gnu
shadow-x86_64-unknown-linux-gnu:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v3" \
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target x86_64-unknown-linux-gnu --profile shadow $(SHADOW_FEATURES) $(SHADOW_CONFIG)

.PHONY: shadow-aarch64-unknown-linux-gnu
shadow-aarch64-unknown-linux-gnu:
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target aarch64-unknown-linux-gnu --profile shadow $(SHADOW_FEATURES) $(SHADOW_CONFIG)

.PHONY: shadow-docker-local
shadow-docker-local: shadow-x86_64-unknown-linux-gnu
	@mkdir -p ./bin/amd64
	@cp ./target/x86_64-unknown-linux-gnu/shadow/lean_client ./bin/amd64/lean_client
	docker build \
		--file Dockerfile \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		$(DOCKER_TAGS) \
		.

.PHONY: help
help:
	@awk '/^## / { \
		sub(/^## /, ""); \
		helpMsg = $$0; \
	} \
	/^[a-zA-Z_-]+:/ { \
		if (helpMsg) { \
			target = $$1; \
			sub(/:/, "", target); \
			printf "\033[36m%-20s\033[0m %s\n", target, helpMsg; \
			helpMsg = ""; \
		} \
	}' $(MAKEFILE_LIST)
