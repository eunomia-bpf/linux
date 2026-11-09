#!/bin/bash
# Format the v2 series, run checkpatch, and build every commit for x86 and arm64.
D=/workspaces/.agent-state/bpf-benchmark-supervisor; S=$D/kfunc-copy-v2; W=$D/kfunc-copy-v2-work
P=$W/patches/check-$(date +%Y%m%d-%H%M); BX=$D/kfunc-copy-v2-bisect-x86; BA=$D/kfunc-copy-v2-bisect-arm64
BASE=a30c772627b2e
cd $S
mkdir -p $P
git format-patch -q --rfc --subject-prefix="PATCH bpf-next" -v2 --cover-letter --base=$BASE -o $P $BASE..kfunc-copy-v2
ls $P
for p in $P/v2-000[1-9]-*.patch; do echo "== $(basename $p)"; ./scripts/checkpatch.pl --strict -q $p | tail -20; done
mkdir -p $BX $BA
if [ ! -f $BX/.config ]; then
  make -s O=$BX defconfig
  ./scripts/config --file $BX/.config -e BPF_SYSCALL -e BPF_JIT -e FTRACE -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e KPROBES
  make -s O=$BX olddefconfig
fi
if [ ! -f $BA/.config ]; then
  make -s O=$BA ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
  ./scripts/config --file $BA/.config -e BPF_SYSCALL -e BPF_JIT -e FTRACE -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e KPROBES
  make -s O=$BA ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
fi
for r in $(git rev-list --reverse $BASE..kfunc-copy-v2); do
  git checkout -q $r
  echo "== $(git log -1 --format=%s)"
  make -s O=$BX -j24 vmlinux 2>&1 | grep -E "error|warning:" | head; echo "x86 rc=${PIPESTATUS[0]}"
  make -s O=$BA ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j24 vmlinux 2>&1 | grep -E "error|warning:" | head; echo "arm64 rc=${PIPESTATUS[0]}"
done
git checkout -q kfunc-copy-v2
echo "== W=1 at tip"
touch arch/x86/net/bpf_jit_comp.c kernel/bpf/core.c kernel/bpf/verifier.c kernel/bpf/helpers.c arch/arm64/net/bpf_jit_comp.c
make -s O=$BX -j24 W=1 arch/x86/net/bpf_jit_comp.o kernel/bpf/core.o kernel/bpf/verifier.o kernel/bpf/helpers.o 2>&1 | grep -E "warning:|error" | head -20
make -s O=$BA ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j24 W=1 arch/arm64/net/bpf_jit_comp.o 2>&1 | grep -E "warning:|error" | head -20
echo check-done
