.PHONY: debug release

debug:
	cargo build
	# CARGO_TARGET_DIR=../target cargo build

clean:
	cargo clean
	# CARGO_TARGET_DIR=../target cargo clean
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    RUSTFLAGS_VAR = '--cfg target_arch="aarch64" --cfg offload="yes"'
else
    RUSTFLAGS_VAR =
endif
release:
	RUSTFLAGS=$(RUSTFLAGS_VAR) cargo build --release

	# CARGO_TARGET_DIR=../target cargo build --release

