#!/bin/bash
# Cross-build test_progs and the test modules for arm64, with the local JITRAW hack.
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; BA=$D/kfunc-copy-v2-build-arm64; OA=$D/kfunc-copy-v2-selftests-arm64
W=$D/kfunc-copy-v2-work; T=$S/tools/testing/selftests/bpf
export PATH=/usr/local/bin:$PATH    # pahole >= 1.32 for the test modules
date -u +%FT%TZ
cp $T/test_loader.c $W/test_loader.c.orig
python3 $W/local_jitraw_hack.py $S
mkdir -p $OA
# the test module objects are shared with the x86 build in the source tree
find $T/test_kmods \( -name "*.o" -o -name "*.ko" -o -name "*.mod" -o -name "*.mod.c" -o -name ".*.cmd" -o -name "Module.symvers" -o -name "modules.order" -o -name ".module-common.o" \) -delete
# the output directory of the other architecture must not be reused: object files are not rebuilds
rm -rf $OA/tools/build
make -C $T -j24 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- SKIP_LLVM=1 SKIP_DOCS=1 \
    CLANG=clang-20 LLC=llc-20 LLVM_STRIP=llvm-strip-20 LLVM_OBJCOPY=llvm-objcopy-20 \
    KBUILD_OUTPUT=$BA VMLINUX_BTF=$BA/vmlinux OUTPUT=$OA $OA/test_progs $OA/bpf_testmod.ko 2>&1 | grep -vE "^  (CC|LD|LINK|GEN|CLANG|INSTALL|BTF|MOD|MODPOST|HOSTCC)"
echo selftests-arm64-rc=${PIPESTATUS[0]}
cp $W/test_loader.c.orig $T/test_loader.c
date -u +%FT%TZ
