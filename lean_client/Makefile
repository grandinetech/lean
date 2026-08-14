### Variables

# Commit of lean specification. Allows to specify which spec version to use,
#   when generating test vectors.
LEAN_SPEC_COMMIT ?= 0f5b8e58e58c0e155ae8b95eabbbde0b9ad8840a
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
# ethereum/hive ref to build. Defaults to latest master, resolved at clone time.
# Override with `make test-hive HIVE_VERSION=<commit>` to pin a specific commit.
HIVE_VERSION ?= master
# Devnet variant of the grandine lean hive client to test. Selects the client
# definition (`simulators/lean/clients/<HIVE_DEVNET>.yaml`) and image
# (`grandine_lean_<HIVE_DEVNET>`). Note: hive uses `devnet5` (no hyphen).
HIVE_DEVNET ?= devnet5

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
	rm -rf ./hive

CLIENT_SOURCES := $(shell find . \
	\( -path './target' -o -path './hive' -o -path './spec' -o -path './bin' \) -prune \
	-o \( -name '*.rs' -o -name 'Cargo.toml' \) -print) Cargo.lock

.PHONY: x86_64-unknown-linux-gnu
x86_64-unknown-linux-gnu: ./target/x86_64-unknown-linux-gnu/release/lean_client

./target/x86_64-unknown-linux-gnu/release/lean_client: $(CLIENT_SOURCES)
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v3" \
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target x86_64-unknown-linux-gnu --profile release

.PHONY: aarch64-unknown-linux-gnu
aarch64-unknown-linux-gnu: ./target/aarch64-unknown-linux-gnu/release/lean_client

./target/aarch64-unknown-linux-gnu/release/lean_client: $(CLIENT_SOURCES)
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

### Hive
.PHONY: test-hive
test-hive: hive/hive docker-local
	@cd hive && \
	./hive --sim lean \
		--client-file simulators/lean/clients/$(HIVE_DEVNET).yaml \
		--client grandine_lean_$(HIVE_DEVNET) \
		--docker.output \
		--docker.nocache="hive/clients/grandine_lean_$(HIVE_DEVNET)" \
		--results-root ./workspace/logs; \
	hive_status=$$?; \
	logs=./workspace/logs; \
	suites=$$(ls $$logs/*.json 2>/dev/null | grep -v '/hive\.json$$' || true); \
	if [ -z "$$suites" ]; then \
		echo "ERROR: hive produced no suite results - treating as an infrastructure/script failure."; \
		exit $$hive_status; \
	fi; \
	if ! command -v jq >/dev/null 2>&1; then \
		echo "jq not found; skipping summary. Raw results under $$logs"; \
		exit $$hive_status; \
	fi; \
	summary=$$( \
		echo "==================== Hive test summary ===================="; \
		total=0; failed_total=0; \
		for f in $$suites; do \
			name=$$(jq -r '.name' "$$f"); \
			n=$$(jq '.testCases | length' "$$f"); \
			nf=$$(jq '[.testCases[] | select(.summaryResult.pass | not)] | length' "$$f"); \
			total=$$((total + n)); failed_total=$$((failed_total + nf)); \
			if [ "$$nf" -eq 0 ]; then \
				printf '%s: %d/%d passed\n' "$$name" "$$n" "$$n"; \
			else \
				printf '%s: %d/%d passed (%d failed)\n' "$$name" "$$((n - nf))" "$$n" "$$nf"; \
				jq -r '.testCases[] | select(.summaryResult.pass | not) | "  FAIL: \(.name)"' "$$f"; \
			fi; \
		done; \
		echo "-----------------------------------------------------------"; \
		printf 'Total: %d/%d passed, %d failed\n' "$$((total - failed_total))" "$$total" "$$failed_total"; \
		echo "Full failure details: lean_client/hive/workspace/logs/details/"; \
		echo "===========================================================" \
	); \
	echo; \
	printf '%s\n' "$$summary"; \
	if [ -n "$$GITHUB_STEP_SUMMARY" ]; then \
		{ echo '```'; printf '%s\n' "$$summary"; echo '```'; } >> "$$GITHUB_STEP_SUMMARY"; \
	fi; \
	exit $$hive_status

hive/hive: hive/.hive-ref-$(HIVE_VERSION)
	@echo "==> Building hive binary (go build)..."
	@cd hive && go build .
	@echo "==> Built hive binary at hive/hive ($$(cd hive && git rev-parse --short HEAD))"

hive/.hive-ref-$(HIVE_VERSION):
	@echo "==> Fetching ethereum/hive at ref '$(HIVE_VERSION)'..."
	@rm -rf hive
	@mkdir -p hive
	@cd hive && git init -q && \
		git remote add origin https://github.com/ethereum/hive.git && \
		git fetch --depth 1 -q origin $(HIVE_VERSION) && \
		git switch -q --detach FETCH_HEAD
	@echo "==> Checked out hive at $$(cd hive && git rev-parse --short HEAD)"
	@touch $@

### Shadow-simulator support
# `rust/patch/quinn-udp` is a vendored fallback-only build of quinn-udp so QUIC
# runs under the Shadow simulator (which does not emulate sendmsg cmsg / GRO /
# GSO / ECN). Applied only for the shadow-* targets via cargo's --config
# override, so prod / devnet builds see the crates.io version.
SHADOW_CONFIG := --config 'patch.crates-io."quinn-udp".path="rust/patch/quinn-udp"'
SHADOW_RUSTFLAGS := --cfg shadow_mode

.PHONY: shadow-build
shadow-build:
	RUSTFLAGS="$(SHADOW_RUSTFLAGS)" cargo build --profile shadow $(SHADOW_CONFIG)

.PHONY: shadow-x86_64-unknown-linux-gnu
shadow-x86_64-unknown-linux-gnu:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v3 $(SHADOW_RUSTFLAGS)" \
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target x86_64-unknown-linux-gnu --profile shadow $(SHADOW_CONFIG)

.PHONY: shadow-aarch64-unknown-linux-gnu
shadow-aarch64-unknown-linux-gnu:
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$(SHADOW_RUSTFLAGS)" \
	LEAN_REPO_ROOT=$(LEAN_REPO_ROOT) cross build --bin lean_client --target aarch64-unknown-linux-gnu --profile shadow $(SHADOW_CONFIG)

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
