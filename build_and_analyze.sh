#!/bin/bash
cd /home/yunwei37/workspace/bpf-benchmark/vendor/linux

# Build analyzer
LIBBPF_DIR=/home/yunwei37/workspace/bpf-benchmark/micro/build/vendor/libbpf

gcc -O2 -I${LIBBPF_DIR}/include -o /tmp/analyze_xlated analyze_xlated.c \
    -L${LIBBPF_DIR} -lbpf -lelf -lz -lzstd 2>&1

if [ $? -ne 0 ]; then
    # Try system libbpf
    gcc -O2 -o /tmp/analyze_xlated analyze_xlated.c -lbpf -lelf -lz 2>&1
fi

echo "=== Analyzing log2_fold.bpf.o ==="
sudo /tmp/analyze_xlated /home/yunwei37/workspace/bpf-benchmark/micro/programs/log2_fold.bpf.o 2>&1

echo ""
echo "=== Analyzing cmov_select.bpf.o ==="
sudo /tmp/analyze_xlated /home/yunwei37/workspace/bpf-benchmark/micro/programs/cmov_select.bpf.o 2>&1
