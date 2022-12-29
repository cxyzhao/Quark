.PHONY: debug release

debug:
	cargo build
	# CARGO_TARGET_DIR=../target cargo build

clean:
	cargo clean
	# CARGO_TARGET_DIR=../target cargo clean
release:
	RUSTFLAGS='--cfg target_arch="aarch64"' cargo build --release
	# CARGO_TARGET_DIR=../target cargo build --release

