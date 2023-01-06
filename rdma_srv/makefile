.PHONY: debug release

debug:
	cargo build
	# CARGO_TARGET_DIR=../target cargo build

clean:
	cargo clean
	# CARGO_TARGET_DIR=../target cargo clean
release:
	RUSTFLAGS='--cfg target_arch="aarch64" --cfg with_doca="yes" -L /opt/mellanox/doca/applications/build/dma_copy/src -L /opt/mellanox/doca/lib/aarch64-linux-gnu -l doca_dma -l doca_common -l doca_sample_common -l doca_common_util -l bsd -l doca_comm_channel -l doca_argp  -l dma_copy_core ' cargo build --release

	# CARGO_TARGET_DIR=../target cargo build --release

