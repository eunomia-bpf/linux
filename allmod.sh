#!/bin/bash
# W=1 build of the files the series touches, under allmodconfig, x86 and arm64.
D=/workspaces/.agent-state/bpf-benchmark-supervisor; S=$D/kfunc-copy-v2
O1=$D/kfunc-copy-v2-allmod-x86; O2=$D/kfunc-copy-v2-allmod-arm64
F="kernel/bpf/core.o kernel/bpf/verifier.o kernel/bpf/helpers.o"
cd $S
make -s O=$O1 allmodconfig && make -s O=$O1 -j24 W=1 $F arch/x86/net/bpf_jit_comp.o 2>&1 | grep -E "warning:|error:" ; echo "x86-allmod rc=${PIPESTATUS[0]}"
make -s O=$O2 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- allmodconfig && make -s O=$O2 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j24 W=1 $F arch/arm64/net/bpf_jit_comp.o 2>&1 | grep -E "warning:|error:"; echo "arm64-allmod rc=${PIPESTATUS[0]}"
echo allmod-done
