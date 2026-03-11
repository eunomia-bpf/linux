#!/bin/bash
# Dump xlated bytecode of log2_fold to understand interior edge structure
MICRO=/home/yunwei37/workspace/bpf-benchmark/micro/build/runner/micro_exec
PROG=/home/yunwei37/workspace/bpf-benchmark/micro/programs/log2_fold.bpf.o
INPUT=/home/yunwei37/workspace/bpf-benchmark/micro/generated-inputs/log2_fold.mem

echo "=== Checking log2_fold with --dump-jit (get native code to inspect) ==="
$MICRO run-kernel \
    --program "$PROG" \
    --memory "$INPUT" \
    --repeat 1 \
    --io-mode staged \
    --recompile-cmov \
    --compile-only 2>&1

echo "=== Check BPF_PROG_JIT_RECOMPILE result code by checking jited_prog_len ==="
# Without recompile
echo "--- Without recompile ---"
$MICRO run-kernel \
    --program "$PROG" \
    --memory "$INPUT" \
    --repeat 1 \
    --io-mode staged \
    --compile-only 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print('jited_prog_len:', d.get('jited_prog_len'), 'result:', d.get('result'))"

echo "--- With recompile ---"
$MICRO run-kernel \
    --program "$PROG" \
    --memory "$INPUT" \
    --repeat 1 \
    --io-mode staged \
    --recompile-cmov \
    --compile-only 2>&1 | grep -v "^libbpf" | python3 -c "import sys,json; lines=sys.stdin.readlines(); [print(l.rstrip()) for l in lines if not l.startswith('{')]; data=[l for l in lines if l.startswith('{')]; [print('jited_prog_len:', json.loads(d).get('jited_prog_len'), 'result:', json.loads(d).get('result')) for d in data]" 2>/dev/null || true
