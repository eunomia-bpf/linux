#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/build-kernel.sh > $W/build-kernel.log 2>&1
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1
bash $W/run-tests.sh -t kfunc_inline,verifier_bpf_fastcall,exceptions > $W/run18.log 2>&1
bash $W/build-arm64.sh > $W/build-arm64.log 2>&1
bash $W/build-selftests-arm64.sh > $W/build-selftests-arm64.log 2>&1
grep -q "selftests-arm64-rc=0" $W/build-selftests-arm64.log && \
	bash $W/run-arm64.sh -t kfunc_inline,verifier_bpf_fastcall > $W/run-arm64-18.log 2>&1
bash $W/check-series.sh > $W/check-series6.log 2>&1
bash $W/allmod.sh > $W/allmod2.log 2>&1
echo done > $W/final5.state
