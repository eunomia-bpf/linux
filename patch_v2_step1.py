"""v2 step 1: keep only live registers across inlined kfuncs; allow byte ops."""
from pathlib import Path

S = Path("/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2")


def edit(rel, pairs):
    p = S / rel
    s = p.read_text()
    for old, new in pairs:
        n = s.count(old)
        if n != 1:
            raise SystemExit(f"{rel}: {n} matches for {old[:60]!r}")
        s = s.replace(old, new)
    p.write_text(s)
    print("edited", rel)


edit("include/linux/bpf_verifier.h", [(
"""	u64 fastcall_spills_num:3;
""",
"""	u64 fastcall_spills_num:3;
	/* for CALL instructions, the registers whose spill/fill pairs in the
	 * bpf_fastcall pattern are removed and must survive the call.
	 */
	u64 fastcall_spilled_regs:6;
""")])

edit("kernel/bpf/verifier.c", [
("""	u32 clobbered_regs_mask;
	struct bpf_call_summary cs;
	u32 expected_regs_mask;
""",
"""	u32 clobbered_regs_mask;
	struct bpf_call_summary cs;
	u32 expected_regs_mask;
	u32 spilled_regs = 0;
"""),
("""		expected_regs_mask &= ~BIT(stx->src_reg);
""",
"""		expected_regs_mask &= ~BIT(stx->src_reg);
		spilled_regs |= BIT(stx->src_reg);
"""),
("""	if (cs.fastcall)
		env->insn_aux_data[insn_idx].fastcall_spills_num = i - 1;
	else
""",
"""	if (cs.fastcall) {
		env->insn_aux_data[insn_idx].fastcall_spills_num = i - 1;
		env->insn_aux_data[insn_idx].fastcall_spilled_regs = spilled_regs;
	} else
"""),
])

x86 = "arch/x86/net/bpf_jit_comp.c"
edit(x86, [
("""/*
 * Return the mask of x86 registers named by an insn of a kfunc or -EINVAL if
 * the insn cannot be copied. Only 32 and 64-bit moves and ALU ops can be:
 * no control flow, prefixes, rip-relative addressing or implicit destination.
 */
static int kfunc_insn_regs(struct insn *insn)
{
	u8 rex = insn->rex_prefix.bytes[0], modrm = insn->modrm.bytes[0], sib = insn->sib.bytes[0];
	u8 ext = X86_MODRM_REG(modrm), idx = X86_SIB_INDEX(sib) | X86_REX_X(rex) << 2;
	u32 op = insn->opcode.bytes[0];
	int regs = 0;
""",
"""/*
 * Without a REX prefix, byte registers 4-7 are ah, ch, dh and bh, the second
 * bytes of rax, rcx, rdx and rbx.
 */
static u32 kfunc_byte_reg_bit(u8 reg, u8 rex)
{
	return !rex && reg >= 4 && reg <= 7 ? BIT(reg - 4) : BIT(reg);
}

/*
 * Return the mask of x86 registers named by an insn of a kfunc or -EINVAL if
 * the insn cannot be copied. Only moves, ALU ops, setcc and byte zero/sign
 * extension can be: no control flow, prefixes, rip-relative addressing or
 * implicit destination.
 */
static int kfunc_insn_regs(struct insn *insn)
{
	u8 rex = insn->rex_prefix.bytes[0], modrm = insn->modrm.bytes[0], sib = insn->sib.bytes[0];
	u8 ext = X86_MODRM_REG(modrm), idx = X86_SIB_INDEX(sib) | X86_REX_X(rex) << 2;
	u8 rm = X86_MODRM_RM(modrm) | X86_REX_B(rex) << 3;
	bool byte_rm = false;
	u32 op = insn->opcode.bytes[0];
	int regs = 0;
"""),
("""	case 0x0fb7: case 0x0fbf:		/* movzx, movsx */
		regs = BIT(ext | X86_REX_R(rex) << 1);
		break;
""",
"""	case 0x0fb7: case 0x0fbf:		/* movzx, movsx */
		regs = BIT(ext | X86_REX_R(rex) << 1);
		break;
	case 0x84:				/* test (byte) */
		regs = kfunc_byte_reg_bit(ext | X86_REX_R(rex) << 1, rex);
		byte_rm = true;
		break;
	case 0x0fb6: case 0x0fbe:		/* movzx, movsx (byte) */
		regs = BIT(ext | X86_REX_R(rex) << 1);
		byte_rm = true;
		break;
	case 0x0f90 ... 0x0f9f:			/* setcc */
		byte_rm = true;
		break;
"""),
("""	if (!insn->sib.nbytes)
		return regs | BIT(X86_MODRM_RM(modrm) | X86_REX_B(rex) << 3);
""",
"""	if (X86_MODRM_MOD(modrm) == 3 && byte_rm)
		return regs | kfunc_byte_reg_bit(rm, rex);
	if (!insn->sib.nbytes)
		return regs | BIT(rm);
"""),
("""/*
 * Inline a KF_FASTCALL kfunc: copy what the compiler generated for it without
 * ENDBR, fentry and 'ret'. bpf_fastcall lets it clobber only R0 and the
 * arguments. Push/pop the other caller saved registers that it uses.
 */
static int emit_kfunc_inline(u8 **pprog, unsigned long addr, const struct btf_func_model *m)
{""",
"""/*
 * Inline a KF_FASTCALL kfunc: copy what the compiler generated for it without
 * ENDBR, fentry and 'ret'. bpf_fastcall lets it clobber only R0 and the
 * arguments. Push/pop the other caller saved registers that it uses and that
 * are @live, the ones whose bpf_fastcall spill/fill the verifier removed.
 */
static int emit_kfunc_inline(u8 **pprog, unsigned long addr, const struct btf_func_model *m,
			     u32 live)
{"""),
("""	for (i = BPF_REG_0; i <= BPF_REG_5; i++) {
		if (i ? i <= m->nr_args : m->ret_size)
			scratch |= x86_reg_bit(i);
		else
			save |= x86_reg_bit(i);
	}
""",
"""	for (i = BPF_REG_0; i <= BPF_REG_5; i++) {
		if (i ? i <= m->nr_args || !(live & BIT(i)) : m->ret_size)
			scratch |= x86_reg_bit(i);
		else
			save |= x86_reg_bit(i);
	}
"""),
("""	return !emit_kfunc_inline(&prog, addr, m);
""",
"""	return !emit_kfunc_inline(&prog, addr, m, GENMASK(BPF_REG_5, BPF_REG_1));
"""),
("""					err = emit_kfunc_inline(&prog, (unsigned long)func, fm);
""",
"""					err = emit_kfunc_inline(&prog, (unsigned long)func, fm,
								env ? env->insn_aux_data[insn_idx].fastcall_spilled_regs :
								      GENMASK(BPF_REG_5, BPF_REG_1));
"""),
])
