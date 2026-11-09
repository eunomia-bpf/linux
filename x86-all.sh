#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/build-kernel.sh > $W/build-kernel.log 2>&1
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1
bash $W/run-tests.sh -vv -t kfunc_inline,verifier_bpf_fastcall > $W/run7.log 2>&1
echo done > $W/x86.done
