all:
	$(MAKE) -C lean_client all

.PHONY: build
build:
	$(MAKE) -C lean_client build

.PHONY: clean
clean:
	$(MAKE) -C lean_client clean

.PHONY: format
format:
	$(MAKE) -C lean_client format

.PHONY: check-format
check-format:
	$(MAKE) -C lean_client check-format

.PHONY: test
test:
	$(MAKE) -C lean_client test

.PHONY: docker
docker:
	$(MAKE) -C lean_client docker

.PHONY: docker-local
docker-local:
	$(MAKE) -C lean_client docker-local

.PHONY: release
release:
	$(MAKE) -C lean_client release
