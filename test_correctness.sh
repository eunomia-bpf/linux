#!/bin/bash
MICRO=/home/yunwei37/workspace/bpf-benchmark/micro/build/runner/micro_exec
PROG_DIR=/home/yunwei37/workspace/bpf-benchmark/micro/programs
INPUT_DIR=/home/yunwei37/workspace/bpf-benchmark/micro/generated-inputs

for bench in log2_fold cmov_select bitcount binary_search; do
    PROG="$PROG_DIR/${bench}.bpf.o"
    MEM="$INPUT_DIR/${bench}.mem"
    [ -f "$PROG" ] || continue
    [ -f "$MEM" ] || continue

    echo "=== $bench ==="

    # Without recompile (baseline)
    result_base=$($MICRO run-kernel \
        --program "$PROG" \
        --memory "$MEM" \
        --repeat 5 \
        --io-mode staged 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result'))")
    echo "  baseline result: $result_base"

    # With recompile
    result_cmov=$($MICRO run-kernel \
        --program "$PROG" \
        --memory "$MEM" \
        --repeat 5 \
        --io-mode staged \
        --recompile-cmov 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result'))")
    echo "  recompile result: $result_cmov"

    if [ "$result_base" = "$result_cmov" ]; then
        echo "  PASS: results match"
    else
        echo "  FAIL: MISMATCH! base=$result_base cmov=$result_cmov"
    fi
    echo ""
done
