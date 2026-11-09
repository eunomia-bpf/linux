// SPDX-License-Identifier: GPL-2.0
/*
 * x86-64 native code of the kinsn operations, see kinsn.c. Without a CPU
 * feature it needs, an operation has none, and the JIT copies the kfunc.
 */
#include <linux/log2.h>
#include <linux/unaligned.h>
#include <linux/cpufeature.h>
#include "kinsn.h"

static u8 *rex(u8 *p, bool w, u8 reg, u8 rm)
{
	u8 b = 0x40 | (w ? 8 : 0) | (reg & 8 ? 4 : 0) | (rm & 8 ? 1 : 0);

	if (b != 0x40)
		*p++ = b;
	return p;
}

/* 64-bit op %reg, %rm */
static u8 *op_rr(u8 *p, u8 op, u8 reg, u8 rm)
{
	p = rex(p, true, reg, rm);
	*p++ = op;
	*p++ = 0xc0 | (reg & 7) << 3 | (rm & 7);
	return p;
}

/*
 * ModRM, SIB and displacement of disp(%base, %index, 1 << scale), with @reg in
 * the reg field. An @index of 4 (%rsp) is none.
 */
static u8 *mem(u8 *p, u8 reg, u8 base, u8 index, u8 scale, s32 disp)
{
	u8 mod = !disp && (base & 7) != 5 ? 0 : disp == (s8)disp ? 1 : 2;
	bool sib = index != 4 || (base & 7) == 4;

	*p++ = mod << 6 | (reg & 7) << 3 | (sib ? 4 : base & 7);
	if (sib)
		*p++ = scale << 6 | (index & 7) << 3 | (base & 7);
	if (mod == 1)
		*p++ = disp;
	if (mod == 2) {
		put_unaligned_le32(disp, p);
		p += 4;
	}
	return p;
}

int kinsn_emit_rol64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	u8 dst = ops->reg[0], src = ops->reg[1], n = ops->imm[BPF_REG_2] & 63, *p = buf;

	if (n && dst != src && boot_cpu_has(X86_FEATURE_BMI2)) {
		/* rorx $(64 - n), %src, %dst */
		*p++ = 0xc4;
		*p++ = (dst & 8 ? 0 : 0x80) | 0x40 | (src & 8 ? 0 : 0x20) | 0x03;
		*p++ = 0xfb;
		*p++ = 0xf0;
		*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
		*p++ = 64 - n;
		return p - buf;
	}
	if (dst != src || !n)
		p = op_rr(p, 0x89, src, dst);	/* mov %src, %dst */
	if (n) {
		/* rol $n, %dst */
		p = rex(p, true, 0, dst);
		*p++ = 0xc1;
		*p++ = 0xc0 | (dst & 7);
		*p++ = n;
	}
	return p - buf;
}

/* cmovcc %src, %dst */
static u8 *cmov(u8 *p, u8 cc, u8 dst, u8 src)
{
	p = rex(p, true, dst, src);
	*p++ = 0x0f;
	*p++ = 0x40 | cc;
	*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
	return p;
}

/*
 * dst = cc ? a : b, after the test or compare at @p. The flags come first, so
 * the result may take the register of an operand they read. A result in the
 * register of a takes b with the inverse condition, which a copy of the
 * compiled kfunc cannot do.
 */
static int emit_select(u8 *buf, u8 *p, u8 cc, u8 dst, u8 a, u8 b)
{
	if (dst == a)
		return cmov(p, cc ^ 1, dst, b) - buf;
	if (dst != b)
		p = op_rr(p, 0x89, b, dst);	/* mov %b, %dst */
	return cmov(p, cc, dst, a) - buf;
}

int kinsn_emit_select64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	u8 cond = ops->reg[1];

	/* test %cond, %cond; cmovne */
	return emit_select(buf, op_rr(buf, 0x85, cond, cond), 0x5, ops->reg[0],
			   ops->reg[2], ops->reg[3]);
}

int kinsn_emit_select_lt64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	/* cmp %y, %x; cmovb */
	return emit_select(buf, op_rr(buf, 0x39, ops->reg[2], ops->reg[1]), 0x2,
			   ops->reg[0], ops->reg[3], ops->reg[4]);
}

/* R4 is free for the control word, as there are three arguments */
int kinsn_emit_extract64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	u8 dst = ops->reg[0], src = ops->reg[1], ctl = dst != src ? dst : ops->reg[4];
	u32 start = ops->imm[BPF_REG_2], len = ops->imm[BPF_REG_3];
	u8 *p = buf;

	if (!boot_cpu_has(X86_FEATURE_BMI1) || start > 63 || !len || len > 64 - start)
		return -EOPNOTSUPP;
	/* mov $(start | len << 8), %ctl */
	p = rex(p, false, 0, ctl);
	*p++ = 0xb8 | (ctl & 7);
	put_unaligned_le32(start | len << 8, p);
	p += 4;
	/* bextr %ctl, %src, %dst */
	*p++ = 0xc4;
	*p++ = (dst & 8 ? 0 : 0x80) | 0x40 | (src & 8 ? 0 : 0x20) | 0x02;
	*p++ = 0x80 | (~ctl & 0xf) << 3;
	*p++ = 0xf7;
	*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
	return p - buf;
}

int kinsn_emit_load_be64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	u8 dst = ops->reg[0], base = ops->reg[1], *p = buf;

	if (!boot_cpu_has(X86_FEATURE_MOVBE))
		return -EOPNOTSUPP;
	/* movbe off(%base), %dst */
	p = rex(p, true, dst, base);
	*p++ = 0x0f;
	*p++ = 0x38;
	*p++ = 0xf0;
	return mem(p, dst, base, 4, 0, ops->imm[BPF_REG_2]) - buf;
}

int kinsn_emit_lea64(const struct bpf_kinsn_operands *ops, u8 *buf)
{
	u8 dst = ops->reg[0], base = ops->reg[1], index = ops->reg[2], *p = buf;
	u32 scale = ops->imm[BPF_REG_3];

	/* %rsp cannot be an index, and the scale is 1, 2, 4 or 8 */
	if (index == 4 || !is_power_of_2(scale) || scale > 8)
		return -EINVAL;
	/* lea disp(%base, %index, scale), %dst */
	*p++ = 0x48 | (dst & 8 ? 4 : 0) | (index & 8 ? 2 : 0) | (base & 8 ? 1 : 0);
	*p++ = 0x8d;
	return mem(p, dst, base, index, ilog2(scale), ops->imm[BPF_REG_4]) - buf;
}
