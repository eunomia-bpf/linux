#!/bin/bash
# Cross-build the v2 tree for arm64 with the BPF selftests config.
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; BA=$D/kfunc-copy-v2-build-arm64; C=$S/tools/testing/selftests/bpf
mkdir -p $BA
date -u +%FT%TZ
cat $C/config.aarch64 $C/config $C/config.vm > $BA/.config
M="make -C $S O=$BA ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)"
$M olddefconfig > /dev/null
grep -E "^CONFIG_(BPF_JIT|DEBUG_INFO_BTF|DYNAMIC_FTRACE_WITH_ARGS|DYNAMIC_FTRACE_WITH_CALL_OPS|ARM64_BTI_KERNEL|ARM64_PTR_AUTH_KERNEL)=" $BA/.config
$M Image modules 2>&1 | grep -E "error|warning:|bpf_jit_comp" | head -40
echo arm64-rc=${PIPESTATUS[0]}
date -u +%FT%TZ
