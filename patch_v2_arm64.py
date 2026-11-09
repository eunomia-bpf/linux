"""v2: let the arm64 JIT inline KF_FASTCALL kfuncs by copying them."""
from pathlib import Path

S = Path("/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2")
p = S / "arch/arm64/net/bpf_jit_comp.c"
s = p.read_text()


def rep(old, new):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{n} matches for {old[:60]!r}")
    s = s.replace(old, new)


rep("""#include <linux/filter.h>
#include <linux/memory.h>
""", """#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>
""")

rep("""/* JITs an eBPF instruction.
""", r"""/* The longest kfunc to inline, in instructions */
#define KFUNC_INLINE_MAX	16

/*
 * Return the mask of registers named by an instruction of a kfunc or -EINVAL
 * if it cannot be copied. Only data processing on registers and immediates
 * can be: no memory access, branch, PC-relative addressing, system instruction
 * or stack pointer. Register 31 is the zero register in the accepted forms.
 */
static s64 kfunc_insn_regs(u32 insn)
{
	u32 rd = insn & 0x1f, rn = (insn >> 5) & 0x1f, rm = (insn >> 16) & 0x1f;
	u32 ra = (insn >> 10) & 0x1f, opcode = (insn >> 10) & 0x3f;
	bool setflags = insn & BIT(29);
	u64 regs;

	if ((insn & 0x1f800000) == 0x11000000) {		/* add/sub (immediate) */
		if (rn == 31 || (rd == 31 && !setflags))
			return -EINVAL;				/* sp */
		regs = BIT(rd) | BIT(rn);
	} else if ((insn & 0x1f800000) == 0x12000000) {	/* logical (immediate) */
		if (rd == 31 && (insn & 0x60000000) != 0x60000000)
			return -EINVAL;				/* sp unless ands */
		regs = BIT(rd) | BIT(rn);
	} else if ((insn & 0x1f800000) == 0x12800000) {	/* move wide */
		regs = BIT(rd);
	} else if ((insn & 0x1f800000) == 0x13000000) {	/* bitfield */
		regs = BIT(rd) | BIT(rn);
	} else if ((insn & 0x1f800000) == 0x13800000 ||	/* extract */
		   (insn & 0x1f000000) == 0x0a000000 ||	/* logical (shifted register) */
		   (insn & 0x1f200000) == 0x0b000000 ||	/* add/sub (shifted register) */
		   (insn & 0x1fe00000) == 0x1a000000 ||	/* add/sub with carry */
		   (insn & 0x1fe00000) == 0x1a800000) {	/* conditional select */
		regs = BIT(rd) | BIT(rn) | BIT(rm);
	} else if ((insn & 0x1fe00000) == 0x1a400000) {	/* conditional compare */
		regs = BIT(rn) | (insn & BIT(11) ? 0 : BIT(rm));
	} else if ((insn & 0x7fe00000) == 0x1ac00000) {	/* data processing (2 source) */
		/* udiv, sdiv, lslv, lsrv, asrv, rorv */
		if (opcode != 2 && opcode != 3 && (opcode < 8 || opcode > 11))
			return -EINVAL;
		regs = BIT(rd) | BIT(rn) | BIT(rm);
	} else if ((insn & 0x7fff0000) == 0x5ac00000) {	/* data processing (1 source) */
		/* rbit, rev16, rev32, rev, clz, cls */
		if (opcode > 5)
			return -EINVAL;
		regs = BIT(rd) | BIT(rn);
	} else if ((insn & 0x1f000000) == 0x1b000000) {	/* data processing (3 source) */
		regs = BIT(rd) | BIT(rn) | BIT(rm) | BIT(ra);
	} else {
		return -EINVAL;
	}
	return regs & ~BIT(31);
}

/*
 * Inline a KF_FASTCALL kfunc: copy what the compiler generated for it without
 * BTI, the ftrace patch site and 'ret', then move its result from x0 to R0.
 * bpf_fastcall lets it clobber only R0 and the arguments. The other caller
 * saved BPF registers that it uses and that are @live, the ones whose
 * bpf_fastcall spill/fill the verifier removed, are kept in registers that no
 * BPF register maps to and that the copied code does not use.
 */
static int emit_kfunc_inline(struct jit_ctx *ctx, u64 addr, const struct btf_func_model *m,
			     u32 live)
{
	/* x5-x7 and x13-x17 hold no BPF register; x9-x12 are the JIT's temporaries */
	const u32 spare = GENMASK(7, 5) | GENMASK(17, 9);
	u32 code[KFUNC_INLINE_MAX], scratch = spare, keep = 0, used = 0, avail, saved[6], insn;
	unsigned long size, off, pc, fentry;
	int i, n = 0, reg;
	s64 regs;

	if (m->nr_args > MAX_BPF_FUNC_REG_ARGS)
		return -EINVAL;
	for (i = 0; i < m->nr_args; i++)
		if (m->arg_size[i] > 8 || (m->arg_flags[i] & BTF_FMODEL_ARENA_ARG))
			return -EINVAL;
	for (i = BPF_REG_0; i <= BPF_REG_5; i++) {
		if (i ? i <= m->nr_args || !(live & BIT(i)) : m->ret_size)
			scratch |= BIT(bpf2a64[i]);
		else
			keep |= BIT(bpf2a64[i]);
	}

	if (!kallsyms_lookup_size_offset(addr, &size, &off) || off)
		return -EINVAL;
	/* the patch site is "NOP; NOP", or "MOV X9, LR; BL <caller>" when traced */
	fentry = ftrace_location(addr);
	if (fentry && !IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_ARGS))
		return -EINVAL;
	for (pc = addr; ; pc += AARCH64_INSN_SIZE) {
		if (pc >= addr + size || aarch64_insn_read((void *)pc, &insn))
			return -EINVAL;
		if ((pc == addr && insn == aarch64_insn_gen_hint(AARCH64_INSN_HINT_BTIC)) ||
		    (fentry && pc + AARCH64_INSN_SIZE >= fentry && pc <= fentry))
			continue;
		if (insn == aarch64_insn_gen_branch_reg(AARCH64_INSN_REG_LR,
							AARCH64_INSN_BRANCH_RETURN))
			break;
		regs = kfunc_insn_regs(insn);
		if (regs < 0)
			return regs;
		if (n == KFUNC_INLINE_MAX)
			return -EINVAL;
		used |= regs;
		code[n++] = insn;
	}
	if (used & ~(scratch | keep))
		return -EINVAL;
	keep &= used;

	/* keep each register in the lowest spare one that the code does not use */
	avail = spare & ~used;
	for (i = 0, reg = 0; i < 31; i++) {
		if (!(keep & BIT(i)))
			continue;
		if (!avail)
			return -EINVAL;
		saved[reg++] = __ffs(avail);
		avail &= avail - 1;
	}
	for (i = 0, reg = 0; i < 31; i++)
		if (keep & BIT(i))
			emit(A64_MOV(1, saved[reg++], i), ctx);
	for (i = 0; i < n; i++)
		emit(code[i], ctx);
	if (m->ret_size)
		emit(A64_MOV(1, bpf2a64[BPF_REG_0], A64_R(0)), ctx);
	for (i = 0, reg = 0; i < 31; i++)
		if (keep & BIT(i))
			emit(A64_MOV(1, i, saved[reg++]), ctx);
	return 0;
}

/* JITs an eBPF instruction.
""")

rep("""			fm = bpf_jit_find_kfunc_model(ctx->prog, insn);
			if (!fm)
				return -EINVAL;
			ret = emit_kfunc_arena_args(ctx, fm);
""", """			fm = bpf_jit_find_kfunc_model(ctx->prog, insn);
			if (!fm)
				return -EINVAL;
			if (fm->ret_flags & BTF_FMODEL_JIT_INLINE) {
				u32 live = GENMASK(BPF_REG_5, BPF_REG_1);

				if (env)
					live = env->insn_aux_data[i + ctx->prog->aux->subprog_start].fastcall_spilled_regs;
				ret = emit_kfunc_inline(ctx, func_addr, fm, live);
				if (ret)
					return ret;
				break;
			}
			ret = emit_kfunc_arena_args(ctx, fm);
""")

rep("""bool bpf_jit_inlines_helper_call(s32 imm)
{""", """bool bpf_jit_inlines_kfunc_call(unsigned long addr, const struct btf_func_model *m)
{
	struct jit_ctx ctx = {};

	return !emit_kfunc_inline(&ctx, addr, m, GENMASK(BPF_REG_5, BPF_REG_1));
}

bool bpf_jit_inlines_helper_call(s32 imm)
{""")

p.write_text(s)
print("edited", p.relative_to(S))
