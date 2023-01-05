.PHONY: debug release

debug:
	CARGO_TARGET_DIR=../target cargo build

release:
	# RUSTFLAGS='--cfg offload="yes"' CARGO_TARGET_DIR=../target cargo build --release

	RUSTFLAGS='--cfg offload="yes" --cfg with_doca="yes" -L /opt/mellanox/doca/applications/build/dma_copy/src -L /opt/mellanox/doca/lib/x86_64-linux-gnu -l doca_common -l doca_sample_common -l doca_common_util' CARGO_TARGET_DIR=../target cargo build --release

