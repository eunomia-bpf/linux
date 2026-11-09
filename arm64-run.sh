#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/run-arm64.sh -vv -t kfunc_inline,verifier_bpf_fastcall > $W/run-arm64.log 2>&1
echo done > $W/arm64.done
