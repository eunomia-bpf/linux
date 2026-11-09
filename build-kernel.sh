#!/bin/bash
# Build the x86_64 kernel with the BPF selftests configuration.
set -e
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; B=$D/kfunc-copy-v2-build
mkdir -p $B
cd $S
if [ ! -f $B/.config ]; then
  make -s O=$B defconfig
  scripts/kconfig/merge_config.sh -m -O $B $B/.config tools/testing/selftests/bpf/config tools/testing/selftests/bpf/config.vm tools/testing/selftests/bpf/config.x86_64 >/dev/null
  make -s O=$B olddefconfig
fi
make -s O=$B olddefconfig
grep PAHOLE_VERSION $B/.config
date -u +%FT%TZ
make -s O=$B -j24 bzImage modules
echo kernel-rc=$?
make -s O=$B olddefconfig
grep PAHOLE_VERSION $B/.config
date -u +%FT%TZ
