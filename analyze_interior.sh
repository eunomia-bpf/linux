#!/bin/bash
# Use bpftool to dump xlated instructions of log2_fold
PROG=/home/yunwei37/workspace/bpf-benchmark/micro/programs/log2_fold.bpf.o

# Load the program first
cat > /tmp/load_and_dump.py << 'EOF'
import ctypes, os, sys, struct, mmap

# BPF constants
BPF_PROG_LOAD = 5
BPF_PROG_GET_FD_BY_ID = 13
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_XDP = 6
BPF_F_XLATED_PROG_INSNS = 0

import subprocess, tempfile, json

# Load program using micro_exec and read its xlated bytecode
# Actually, let's use bpftool directly
result = subprocess.run(['bpftool', 'prog', 'loadall',
                        '/home/yunwei37/workspace/bpf-benchmark/micro/programs/log2_fold.bpf.o',
                        '/sys/fs/bpf/test_log2fold'],
                       capture_output=True, text=True)
print("load:", result.returncode, result.stderr[:200])

result2 = subprocess.run(['bpftool', 'prog', 'list'], capture_output=True, text=True)
print("prog list:", result2.stdout[:500])

result3 = subprocess.run(['bpftool', 'prog', 'dump', 'xlated', 'name', 'log2_fold_xdp'],
                        capture_output=True, text=True)
print("xlated dump:\n", result3.stdout[:3000])
print("xlated stderr:", result3.stderr[:200])

# Cleanup
subprocess.run(['rm', '-rf', '/sys/fs/bpf/test_log2fold'], capture_output=True)
EOF
python3 /tmp/load_and_dump.py
