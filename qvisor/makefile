.PHONY: debug release

debug:
	CARGO_TARGET_DIR=../target cargo build

release:
	RUSTFLAGS='--cfg offload="yes"' CARGO_TARGET_DIR=../target cargo build --release

