// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kinsns: kfuncs that BPF programs use as instructions. The verifier analyzes
 * each call as the BPF instructions of the kinsn, and the JIT puts native code
 * in place of the call when it has some.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

static struct bpf_kfunc_desc *kinsn_desc(struct bpf_verifier_env *env,
					 const struct bpf_insn *insn)
{
	struct bpf_kfunc_desc *desc;

	if (!bpf_pseudo_kfunc_call(insn))
		return NULL;
	desc = bpf_find_kfunc_desc(env->prog, insn->imm, insn->off);
	return desc && desc->kinsn ? desc : NULL;
}

/*
 * Replace each kinsn call with the instructions of the kinsn, so that the
 * verifier analyzes the operation in the caller's context. Their entry and
 * exits get the register effects of the call, see bpf_mark_kinsn_regs().
 * After verification bpf_restore_kinsns() puts the call back if the JIT has
 * native code for it, and keeps the instructions otherwise.
 */
int bpf_lower_kinsns(struct bpf_verifier_env *env)
{
	struct bpf_kfunc_desc *desc;
	struct bpf_kinsn_region *r;
	struct bpf_prog *prog;
	u32 i, j, cnt = 0;

	for (i = 0; i < env->prog->len; i++)
		cnt += !!kinsn_desc(env, &env->prog->insnsi[i]);
	if (!cnt)
		return 0;
	env->kinsns = kvzalloc_objs(*env->kinsns, cnt, GFP_KERNEL_ACCOUNT);
	if (!env->kinsns)
		return -ENOMEM;

	for (i = 0; i < env->prog->len; i++) {
		desc = kinsn_desc(env, &env->prog->insnsi[i]);
		if (!desc)
			continue;
		r = &env->kinsns[env->kinsn_cnt++];
		r->call = env->prog->insnsi[i];
		r->kinsn = desc->kinsn;
		r->addr = desc->addr;
		r->start = i;
		r->nargs = desc->func_model.nr_args;
		r->imm_mask = desc->kinsn_imm;
		r->ret = desc->func_model.ret_size;
		prog = bpf_patch_insn_data(env, i, r->kinsn->insns, r->kinsn->len);
		if (!prog)
			return -ENOMEM;
		env->prog = prog;
		for (j = i; j < i + r->kinsn->len; j++)
			env->insn_aux_data[j].kinsn = 1;
		env->insn_aux_data[i].kinsn_entry = 1;
		i += r->kinsn->len - 1;
	}
	return 0;
}

/*
 * The instructions of a kinsn get only the arguments of the call and leave
 * R1-R5 like it. Its constant (__k) arguments must be known, and native code
 * may use their values.
 */
int bpf_mark_kinsn_regs(struct bpf_verifier_env *env, int prev_insn_idx,
			const struct bpf_insn_aux_data *aux)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_kinsn_region *r = env->kinsns;
	u32 clobber = 0;
	int i, err;

	if (prev_insn_idx >= 0 && bpf_kinsn_exit(env, prev_insn_idx, env->insn_idx))
		clobber |= GENMASK(BPF_REG_5, BPF_REG_1);
	if (aux->kinsn_entry) {
		while (r->start != env->insn_idx)
			r++;
		for (i = BPF_REG_1; i <= BPF_REG_5 && !env->cur_state->speculative; i++) {
			if (!(r->imm_mask & BIT(i)))
				continue;
			if (regs[i].type != SCALAR_VALUE || !tnum_is_const(regs[i].var_off)) {
				verbose(env, "R%d must be a known constant\n", i);
				return -EINVAL;
			}
			err = mark_chain_precision(env, i);
			if (err)
				return err;
			if (r->entered && r->ops.imm[i] != (s32)regs[i].var_off.value)
				r->imm_differ = true;
			r->ops.imm[i] = regs[i].var_off.value;
		}
		r->entered = true;
		clobber |= BIT(BPF_REG_0) | (GENMASK(BPF_REG_5, BPF_REG_0) &
					     ~GENMASK(r->nargs, BPF_REG_0));
	}
	for (i = BPF_REG_0; i <= BPF_REG_5; i++) {
		if (!(clobber & BIT(i)))
			continue;
		bpf_mark_reg_not_init(env, &regs[i]);
		mark_reg_scratched(env, i);
	}
	return 0;
}

/*
 * Native code can replace the instructions of a kinsn that the verifier
 * reached and does not rewrite later: no speculation barriers, sanitation or
 * arena conversion, and memory accesses only to memory that the JIT accesses
 * as is.
 */
static bool kinsn_native_ok(struct bpf_verifier_env *env, const struct bpf_kinsn_region *r)
{
	u32 i;

	if (env->prog->blinding_requested || (r->imm_mask && !r->entered))
		return false;
	for (i = 0; i < r->kinsn->len; i++) {
		const struct bpf_insn_aux_data *aux = &env->insn_aux_data[r->start + i];
		u8 class = BPF_CLASS(r->kinsn->insns[i].code);

		if (aux->nospec || aux->nospec_result || aux->alu_state || aux->needs_zext ||
		    aux->arena_scalar)
			return false;
		if (class != BPF_LDX && class != BPF_STX && class != BPF_ST)
			continue;
		if (type_flag(aux->ptr_type) & ~MEM_RDONLY)
			return false;
		switch (base_type(aux->ptr_type)) {
		case PTR_TO_STACK:
		case PTR_TO_MAP_VALUE:
		case PTR_TO_MEM:
		case PTR_TO_PACKET:
		case PTR_TO_PACKET_META:
			break;
		default:
			return false;
		}
	}
	return true;
}

/*
 * Bind the operands of a kinsn call in r->ops and return the moves that this
 * makes unnecessary in @drop:
 * - an argument copied from R6-R9 by a 64-bit move right before the call is
 *   used in place if that register is dead after the call;
 * - emitted native code has the constant arguments as immediates;
 * - the result goes straight to its R6-R9 destination.
 * No jump may land between such a move and the call. Only emitted code may
 * share the result register with an argument.
 */
static int kinsn_bind(struct bpf_verifier_env *env, struct bpf_kinsn_region *r, u32 *drop)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insns = env->prog->insnsi, *mov;
	u32 end = r->start + r->kinsn->len, i;
	bool emit = !r->copy;
	u16 used = 0, written = 0;
	u8 dst, src;
	int n = 0;

	for (i = 0; i <= MAX_BPF_FUNC_REG_ARGS; i++)
		r->ops.reg[i] = i;

	/* walk back over moves into R1-R5 that do not read R0-R5 */
	for (i = r->start; i-- > 0 && !bpf_is_jump_target(env, i + 1);) {
		mov = &insns[i];
		dst = mov->dst_reg;
		src = mov->src_reg;
		if ((BPF_CLASS(mov->code) != BPF_ALU64 && BPF_CLASS(mov->code) != BPF_ALU) ||
		    BPF_OP(mov->code) != BPF_MOV || dst < BPF_REG_1 || dst > BPF_REG_5 ||
		    aux[i].kinsn ||
		    (BPF_SRC(mov->code) == BPF_X && (src < BPF_REG_6 || src > BPF_REG_9)))
			break;
		if (dst <= r->nargs && !(written & BIT(dst)) && !mov->off) {
			if (BPF_SRC(mov->code) == BPF_K && (r->imm_mask & BIT(dst)) && emit) {
				drop[n++] = i;
			} else if (mov->code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
				   !(used & BIT(src)) &&
				   !(aux[end].live_regs_before & BIT(src))) {
				r->ops.reg[dst] = src;
				used |= BIT(src);
				drop[n++] = i;
			}
		}
		written |= BIT(dst);
	}

	mov = &insns[end];
	dst = mov->dst_reg;
	/* the result register must be live so that the JIT saves it */
	if (r->ret && !bpf_is_jump_target(env, end) && end + 1 < env->prog->len &&
	    mov->code == (BPF_ALU64 | BPF_MOV | BPF_X) && !mov->off &&
	    mov->src_reg == BPF_REG_0 && dst >= BPF_REG_6 && dst <= BPF_REG_9 &&
	    (emit || !(used & BIT(dst))) &&
	    (aux[end + 1].live_regs_before & BIT(dst)) &&
	    !(aux[end + 1].live_regs_before & BIT(BPF_REG_0))) {
		r->ops.reg[BPF_REG_0] = dst;
		drop[n++] = end;
	}
	return n;
}

/*
 * Put back the calls that the JIT has native code for: the kinsn's own code,
 * or else a copy of the compiled kfunc. The rest of the instructions and the
 * moves that binding makes unnecessary become nops, which
 * bpf_opt_remove_nops() removes. Other calls keep their instructions.
 */
void bpf_restore_kinsns(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi;
	u32 drop[MAX_BPF_FUNC_REG_ARGS + 1];
	u8 code[BPF_KINSN_MAX_EMIT];
	int i, j, n, len;

	for (i = 0; i < env->kinsn_cnt; i++) {
		struct bpf_kinsn_region *r = &env->kinsns[i];

		if (!kinsn_native_ok(env, r))
			continue;
		r->copy = !r->kinsn->emit || r->imm_differ;
		n = kinsn_bind(env, r, drop);
		len = bpf_jit_emit_kinsn(r, code);
		if (len <= 0 && !r->copy) {
			r->copy = true;
			n = kinsn_bind(env, r, drop);
			len = bpf_jit_emit_kinsn(r, code);
		}
		r->image = len > 0 ? kmemdup(code, len, GFP_KERNEL_ACCOUNT) : NULL;
		if (!r->image)
			continue;
		r->image_len = len;
		for (j = 0; j < n; j++)
			insns[drop[j]] = BPF_JMP_A(0);
		insns[r->start] = r->call;
		for (j = r->start + 1; j < r->start + r->kinsn->len; j++)
			insns[j] = BPF_JMP_A(0);
		env->insn_aux_data[r->start].kinsn_call = i + 1;
	}
}

/* The kinsn call at @idx, a kfunc call, if the JIT puts native code there */
const struct bpf_kinsn_region *bpf_kinsn_native(const struct bpf_verifier_env *env, int idx)
{
	u32 i = env && env->insn_aux_data[idx].kinsn_entry ?
		env->insn_aux_data[idx].kinsn_call : 0;

	if (!i || i > env->kinsn_cnt || !env->kinsns[i - 1].image)
		return NULL;
	return &env->kinsns[i - 1];
}

void bpf_free_kinsns(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->kinsn_cnt; i++)
		kfree(env->kinsns[i].image);
	kvfree(env->kinsns);
}
