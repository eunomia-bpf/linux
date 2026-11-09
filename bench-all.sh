#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1
for r in 1 2; do
  bash $W/run-bench.sh inline >> $W/bench3.log 2>&1
  bash $W/run-bench.sh call bpf_kfunc_inline_off >> $W/bench3.log 2>&1
done
echo done > $W/bench3.state
