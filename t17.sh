#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1
bash $W/run-tests.sh -t kfunc_inline,verifier_bpf_fastcall > $W/run17.log 2>&1
bash $W/build-selftests-arm64.sh > $W/build-selftests-arm64.log 2>&1
grep -q "selftests-arm64-rc=0" $W/build-selftests-arm64.log && \
	bash $W/run-arm64.sh -t kfunc_inline,verifier_bpf_fastcall > $W/run-arm64-t17.log 2>&1
echo done > $W/t17.state
