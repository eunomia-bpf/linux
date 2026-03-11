#!/bin/bash
# Test interior edge fix: log2_fold and cmov_select

MICRO=/home/yunwei37/workspace/bpf-benchmark/micro/build/runner/micro_exec
PROG_DIR=/home/yunwei37/workspace/bpf-benchmark/micro/programs
INPUT_DIR=/home/yunwei37/workspace/bpf-benchmark/micro/generated-inputs

echo "=== Testing log2_fold (has interior edge, should be REJECTED by validator) ==="
echo "Expected: BPF_PROG_JIT_RECOMPILE failed (all sites rejected) OR correct result=9"
$MICRO run-kernel \
    --program "$PROG_DIR/log2_fold.bpf.o" \
    --memory "$INPUT_DIR/log2_fold.mem" \
    --repeat 5 \
    --io-mode staged \
    --recompile-cmov 2>&1
echo ""

echo "=== Testing cmov_select (no interior edge, should be ACCEPTED) ==="
echo "Expected: recompile succeeds, result correct"
$MICRO run-kernel \
    --program "$PROG_DIR/cmov_select.bpf.o" \
    --memory "$INPUT_DIR/cmov_select.mem" \
    --repeat 5 \
    --io-mode staged \
    --recompile-cmov 2>&1
