#!/bin/bash
# Analyze xlated bytecode of log2_fold using BPF syscalls directly
cat > /tmp/analyze_xlated.py << 'PYEOF'
import ctypes, os, struct, subprocess, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)
NR_bpf = 321  # x86_64

class bpf_attr_prog_load(ctypes.Structure):
    _fields_ = [
        ("prog_type", ctypes.c_uint32),
        ("insn_cnt", ctypes.c_uint32),
        ("insns", ctypes.c_uint64),
        ("license", ctypes.c_uint64),
        ("log_level", ctypes.c_uint32),
        ("log_size", ctypes.c_uint32),
        ("log_buf", ctypes.c_uint64),
        ("kern_version", ctypes.c_uint32),
        ("prog_flags", ctypes.c_uint32),
        ("prog_name", ctypes.c_char * 16),
        ("prog_ifindex", ctypes.c_uint32),
        ("expected_attach_type", ctypes.c_uint32),
    ]

# Use micro_exec to get program info -- actually let's parse the xlated via
# the BPF_PROG_GET_FD_BY_ID + BPF_OBJ_GET_INFO_BY_FD approach
# But we need a loaded program. Let's use subprocess to load via micro_exec
# and then introspect.

# Actually, let's just read the raw BPF bytes from the ELF
import subprocess

# Read xlated instructions using BPF PROG_LOAD then GET_INFO
# Much simpler: parse from the .bpf.o ELF and run through our own scanner

# Load the object and get xlated insns by using a helper
# Let's write a C approach instead - use the raw xlated dump from micro_exec

# Best approach: intercept the xlated program in the runner
# Let's use a different approach - just dump the BPF insns from the loaded prog

# Use BPF_PROG_GET_NEXT_ID + BPF_PROG_GET_FD_BY_ID + BPF_OBJ_GET_INFO_BY_FD
def bpf_syscall(cmd, attr_bytes):
    buf = (ctypes.c_char * len(attr_bytes))(*attr_bytes)
    ret = libc.syscall(NR_bpf, ctypes.c_int(cmd), ctypes.byref(buf), ctypes.c_uint32(len(attr_bytes)))
    return ret, bytes(buf)

# First, we need to load the program. Let's use a subprocess that loads it
# and gets us the prog_id.
# Easier: use /proc to look at loaded programs after micro_exec pins it
import tempfile, threading, time, signal

# Load program in background using micro_exec, get prog id from /proc
prog_path = "/home/yunwei37/workspace/bpf-benchmark/micro/programs/log2_fold.bpf.o"
input_path = "/home/yunwei37/workspace/bpf-benchmark/micro/generated-inputs/log2_fold.mem"
micro_exec = "/home/yunwei37/workspace/bpf-benchmark/micro/build/runner/micro_exec"

# Start micro_exec with compile-only
result = subprocess.run([micro_exec, "run-kernel", "--program", prog_path,
                        "--memory", input_path, "--repeat", "1",
                        "--io-mode", "staged", "--compile-only"],
                       capture_output=True, text=True)
print("micro_exec stdout:", result.stdout[:200])
print("micro_exec stderr:", result.stderr[:500])

# After the program is loaded, query BPF_PROG_GET_NEXT_ID
# Note: program is likely unloaded by now since micro_exec exited
# Let's try: load program, immediately dump, then exit

# Alternative: parse the ELF section directly with pyelftools
try:
    import elftools.elf.elffile as elf_mod
    with open(prog_path, "rb") as f:
        elf = elf_mod.ELFFile(f)
    for section in elf.iter_sections():
        if section.name == "xdp":
            data = section.data()
            insn_cnt = len(data) // 8
            print(f"\nFound xdp section: {insn_cnt} instructions")

            # Decode each instruction
            for i in range(insn_cnt):
                b = data[i*8:(i+1)*8]
                code, regs, off, imm = struct.unpack("<BBHI", b)[:4]
                # Actually: code(1), regs(1), off(2s), imm(4s)
                code = b[0]
                regs = b[1]
                dst = regs & 0xF
                src = (regs >> 4) & 0xF
                off = struct.unpack("<h", b[2:4])[0]
                imm = struct.unpack("<i", b[4:8])[0]

                cls = code & 0x07
                op = code & 0xF0
                src_mode = (code >> 3) & 0x01

                is_jmp = (cls == 0x05 or cls == 0x06)
                if is_jmp:
                    target = i + 1 + off
                    if op == 0x00:  # JA
                        print(f"  [{i:3d}] JMP code=0x{code:02x} off={off:4d} -> target={target}")
                    else:
                        print(f"  [{i:3d}] JCC code=0x{code:02x} dst={dst} src={src} off={off:4d} -> target={target}")
            break
except ImportError:
    print("pyelftools not available")
    # Fallback: just show raw hex
    with open(prog_path, "rb") as f:
        data = f.read(100)
    print("First 100 bytes:", data.hex())

PYEOF
python3 /tmp/analyze_xlated.py 2>&1
