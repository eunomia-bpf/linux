#!/bin/bash
W=/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2-work
bash $W/build-selftests.sh > $W/build-selftests.log 2>&1; echo "build rc=$?" >> $W/build-selftests.log
bash $W/run-tests.sh -vv -t kfunc_inline > $W/run6.log 2>&1
echo done > $W/bt.done
