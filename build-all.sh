#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
$W/build-kernel.sh > $W/build-kernel.log 2>&1 && grep -q kernel-rc=0 $W/build-kernel.log && $W/build-selftests.sh > $W/build-selftests.log 2>&1
echo BUILD-ALL-DONE
