#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
while pgrep -f allmod.sh >/dev/null; do sleep 10; done
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1
bash $W/run-tests.sh -t kfunc_inline,verifier_bpf_fastcall > $W/run16.log 2>&1
echo done > $W/t16.state
