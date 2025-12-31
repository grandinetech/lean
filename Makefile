.PHONY: build format check-format test

all:
	$(MAKE) -C lean_client all

build:
	$(MAKE) -C lean_client build

format:
	$(MAKE) -C lean_client format

check-format:
	$(MAKE) -C lean_client check-format

test:
	$(MAKE) -C lean_client test
