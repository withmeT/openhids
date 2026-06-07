# Prebuilt eBPF object

`hids.bpf` is linked at agent build time (`include_bytes` in `agent.rs`).

- **Normal build** (no network): `cargo build --release` copies this file to `OUT_DIR/hids`.
- **Rebuild from `hids-ebpf` sources** (needs network + nightly):  
  `AYA_BUILD_EBPF=1 cargo build --release`

After recompiling eBPF, refresh the blob:

```bash
cp ../target/release/build/hids-*/out/hids ebpf/hids.bpf
```
