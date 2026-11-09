// SPDX-License-Identifier: GPL-2.0
/*
 * Kfuncs that BPF programs use as instructions. The verifier checks each call
 * as the BPF instructions below. The JIT puts the native code of the
 * architecture in place of the call, or a copy of the compiled kfunc, see
 * struct bpf_kinsn. Arguments named __k must be known constants.
 */
#include <linux/bitops.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/unaligned.h>
#include "kinsn.h"

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_kinsn_rol64(u64 x, u32 n__k)
{
	return rol64(x, n__k);
}

__bpf_kfunc u64 bpf_kinsn_select64(u64 cond, u64 a, u64 b)
{
	return cond ? a : b;
}

__bpf_kfunc u64 bpf_kinsn_select_lt64(u64 x, u64 y, u64 a, u64 b)
{
	return x < y ? a : b;
}

__bpf_kfunc u64 bpf_kinsn_extract64(u64 x, u32 start__k, u32 len__k)
{
	return x << (64 - start__k - len__k) >> (64 - len__k);
}

__bpf_kfunc u64 bpf_kinsn_load_be64(const void *p, s32 off__k)
{
	return get_unaligned_be64(p + off__k);
}

__bpf_kfunc void bpf_kinsn_prefetch(const void *p)
{
	/* prefetcht0, which boot-time alternatives do not rewrite */
	__builtin_prefetch(p);
}

__bpf_kfunc void bpf_kinsn_copy16(void *dst, const void *src)
{
	memcpy(dst, src, 16);
}

__bpf_kfunc u64 bpf_kinsn_lea64(u64 base, u64 index, u32 scale__k, s32 disp__k)
{
	return base + index * scale__k + disp__k;
}

__bpf_kfunc_end_defs();

/* x << n | x >> (-n & 63) */
static const struct bpf_insn rol64_insns[] = {
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 63),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 63),
	BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2),
	BPF_ALU64_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
};

/* jumps land within the instructions, here on the last one */
static const struct bpf_insn select64_insns[] = {
	BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 1),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
};

static const struct bpf_insn select_lt64_insns[] = {
	BPF_JMP_REG(BPF_JLT, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_4),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_3),
};

/* x << (64 - start - len) >> (64 - len) */
static const struct bpf_insn extract64_insns[] = {
	BPF_MOV32_IMM(BPF_REG_4, 64),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_2),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_4),
	BPF_MOV32_IMM(BPF_REG_4, 64),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_3),
	BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_4),
};

/* the offset is an s32 */
static const struct bpf_insn load_be64_insns[] = {
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_2, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),
	BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 64),
};

/* a load whose value is not used, of memory that the program may read */
static const struct bpf_insn prefetch_insns[] = {
	BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_1, 0),
};

/* two loads, then two stores */
static const struct bpf_insn copy16_insns[] = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_2, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_2, 8),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_4, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_5, 8),
};

/* base + index * scale + disp, scale a u32 and disp an s32 */
static const struct bpf_insn lea64_insns[] = {
	BPF_MOV32_REG(BPF_REG_3, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_REG(BPF_MUL, BPF_REG_0, BPF_REG_3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 32),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_4, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_4),
};

BTF_KFUNCS_START(kinsn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_kinsn_rol64)
BTF_ID_FLAGS(func, bpf_kinsn_select64)
BTF_ID_FLAGS(func, bpf_kinsn_select_lt64)
BTF_ID_FLAGS(func, bpf_kinsn_extract64)
BTF_ID_FLAGS(func, bpf_kinsn_load_be64)
BTF_ID_FLAGS(func, bpf_kinsn_prefetch)
BTF_ID_FLAGS(func, bpf_kinsn_copy16)
BTF_ID_FLAGS(func, bpf_kinsn_lea64)
BTF_KFUNCS_END(kinsn_kfunc_ids)

BTF_ID_LIST(kinsn_ids)
BTF_ID(func, bpf_kinsn_rol64)
BTF_ID(func, bpf_kinsn_select64)
BTF_ID(func, bpf_kinsn_select_lt64)
BTF_ID(func, bpf_kinsn_extract64)
BTF_ID(func, bpf_kinsn_load_be64)
BTF_ID(func, bpf_kinsn_prefetch)
BTF_ID(func, bpf_kinsn_copy16)
BTF_ID(func, bpf_kinsn_lea64)

#define KINSN(i, op, emit)	{ &kinsn_ids[i], op##_insns, ARRAY_SIZE(op##_insns), emit }

/* without emit, the JIT copies the kfunc, whose code is the instruction itself */
static const struct bpf_kinsn kinsns[] = {
	KINSN(0, rol64, KINSN_EMIT(rol64)),
	KINSN(1, select64, KINSN_EMIT(select64)),
	KINSN(2, select_lt64, KINSN_EMIT(select_lt64)),
	KINSN(3, extract64, KINSN_EMIT(extract64)),
	KINSN(4, load_be64, KINSN_EMIT(load_be64)),
	KINSN(5, prefetch, NULL),
	KINSN(6, copy16, NULL),
	KINSN(7, lea64, KINSN_EMIT(lea64)),
};

static const struct btf_kfunc_id_set kinsn_set = {
	.set = &kinsn_kfunc_ids,
	.kinsns = kinsns,
	.kinsn_cnt = ARRAY_SIZE(kinsns),
};

static int __init kinsn_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &kinsn_set);
}
late_initcall(kinsn_init);
