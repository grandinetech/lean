### Variables

# Commit of lean specification. Allows to specify which spec version to use, 
#   when generating test vectors. Currently set to devnet-2 spec version.
LEAN_SPEC_COMMIT ?= 4edcf7bc9271e6a70ded8aff17710d68beac4266
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
CURRENT_DEVNET := devnet-1

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
	cd spec && uv run fill --clean --fork=devnet --scheme prod
	rm -rf ./test_vectors && mkdir -p ./test_vectors
	cp -r ./spec/fixtures/consensus/* ./test_vectors/

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
