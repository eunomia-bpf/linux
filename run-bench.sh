#!/bin/bash
# LOCAL benchmark: run-bench.sh <label> [kernel cmdline]
D=/workspaces/.agent-state/bpf-benchmark-supervisor
S=$D/kfunc-copy-v2; B=$D/kfunc-copy-v2-build; T=$S/tools/testing/selftests/bpf
APPEND=()
[ -n "$2" ] && APPEND=(--append "$2")
cd $T
timeout 1200 vng --run $B/arch/x86/boot/bzImage --cpus 4 --memory 4G --user root --rwdir $T "${APPEND[@]}"     --exec "cat /proc/cmdline; cd $T && ./test_progs -v -t kfunc_inline_bench,kfunc_inline" 2>&1 | grep -E "BENCH|^#|Summary|cmdline|bpf_kfunc_inline_off" | sed "s/^/$1: /"
