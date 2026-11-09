#!/bin/bash
# Build the BPF selftests against the v2 kernel build with clang-20.
# usage: build-selftests.sh [extra make targets]  (default: everything)
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; B=$D/kfunc-copy-v2-build
export PATH=/usr/local/bin:$PATH    # pahole >= 1.32 for the test modules
rm -rf $S/tools/testing/selftests/bpf/tools/build 2>/dev/null || true   # output only; the tree is shared with the arm64 build
date -u +%FT%TZ
make -C $S/tools/testing/selftests/bpf -j24 CLANG=clang-20 LLC=llc-20 LLVM_STRIP=llvm-strip-20 \
    LLVM_OBJCOPY=llvm-objcopy-20 KBUILD_OUTPUT=$B VMLINUX_BTF=$B/vmlinux ${@:-} 2>&1 | tail -40
echo selftests-rc=${PIPESTATUS[0]}
date -u +%FT%TZ
