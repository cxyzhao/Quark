.PHONY: debug release

debug:
	cargo build
	# CARGO_TARGET_DIR=../target cargo build

clean:
	cargo clean
	# CARGO_TARGET_DIR=../target cargo clean

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    RUSTFLAGS_VAR = --cfg offload=\"yes\" --cfg gvmi=\"no\" --cap-lints warn
    TARGET_SPEC = --target aarch64-unknown-linux-gnu
else
    RUSTFLAGS_VAR =
    TARGET_SPEC =
endif

release:
	RUSTFLAGS="$(RUSTFLAGS_VAR)" cargo +nightly build --release $(TARGET_SPEC)

