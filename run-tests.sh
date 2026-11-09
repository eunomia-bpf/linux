#!/bin/bash
# Run test_progs selectors in a fresh vng guest on the v2 kernel: run-tests.sh <test_progs args...>
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; B=$D/kfunc-copy-v2-build
cd $S/tools/testing/selftests/bpf
timeout 1200 vng --run $B/arch/x86/boot/bzImage --cpus 4 --memory 4G --user root --rwdir $S/tools/testing/selftests/bpf \
    --exec "cd $S/tools/testing/selftests/bpf && ./test_progs $*" 2>&1 | tail -20000
