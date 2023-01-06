.PHONY: debug release

debug:
	CARGO_TARGET_DIR=../target cargo build

release:
	# RUSTFLAGS='--cfg offload="yes"' CARGO_TARGET_DIR=../target cargo build --release

	RUSTFLAGS='--cfg offload="yes" --cfg with_doca="yes" -L /opt/mellanox/doca/applications/build/dma_copy/src -L /opt/mellanox/doca/lib/x86_64-linux-gnu -l doca_dma -l doca_common -l doca_sample_common -l doca_common_util -l bsd -l doca_comm_channel -l doca_argp  -l dma_copy_core' CARGO_TARGET_DIR=../target cargo build --release

