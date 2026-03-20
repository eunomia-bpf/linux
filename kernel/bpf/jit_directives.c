// SPDX-License-Identifier: GPL-2.0-only
/* BPF JIT policy framework (v5 declarative patterns only) */
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/bpf_verifier.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>
#include <uapi/linux/fcntl.h>
#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#endif

#define BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE SZ_512K
#define BPF_JIT_RECOMPILE_LOG_MAX_SIZE SZ_64K
#define BPF_JIT_MAX_RULES		1024

struct bpf_jit_recompile_prog_state {
	struct bpf_prog *prog;
	bpf_func_t bpf_func;
	void __percpu *priv_stack_ptr;
	struct exception_table_entry *extable;
	void *jit_data;
	struct bpf_insn *insnsi_copy;
	u32 insn_cnt;
	u32 jited_len;
	u32 num_exentries;
	bool jited;
	bool exception_boundary;
};

struct bpf_jit_recompile_rollback_state {
	struct bpf_prog_aux *main_aux;
	u64 (*bpf_exception_cb)(u64 cookie, u64 sp, u64 bp, u64, u64);
	struct bpf_jit_recompile_prog_state *prog_states;
	u32 prog_state_cnt;
};

void bpf_jit_recompile_prog_log(const struct bpf_prog *prog, const char *fmt, ...)
{
	struct bpf_verifier_log *log;
	va_list args;

	if (!prog || !prog->aux)
		return;

	log = bpf_prog_main_aux(prog)->jit_recompile_log;
	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

void bpf_jit_recompile_rule_log(const struct bpf_prog *prog,
				const struct bpf_jit_rule *rule,
				const char *fmt, ...)
{
	struct bpf_verifier_log *log;
	u32 site_end = 0;
	va_list args;

	if (!prog || !prog->aux || !rule)
		return;

	log = bpf_prog_main_aux(prog)->jit_recompile_log;
	if (!bpf_verifier_log_needed(log))
		return;

	if (!check_add_overflow(rule->site_start,
				rule->site_len ? rule->site_len - 1 : 0,
				&site_end)) {
		bpf_log(log, "rule %u: form %u site %u-%u: ",
			rule->user_index, rule->canonical_form,
			rule->site_start, site_end);
	} else {
		bpf_log(log, "rule %u: form %u site %u: ",
			rule->user_index, rule->canonical_form,
			rule->site_start);
	}

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
	bpf_log(log, "\n");
}

static void
bpf_jit_recompile_save_prog_state(struct bpf_jit_recompile_prog_state *state,
				  struct bpf_prog *prog)
{
	state->prog = prog;
	state->bpf_func = prog->bpf_func;
	state->priv_stack_ptr = prog->aux->priv_stack_ptr;
	state->extable = prog->aux->extable;
	state->jit_data = prog->aux->jit_data;
	state->jited_len = prog->jited_len;
	state->num_exentries = prog->aux->num_exentries;
	state->jited = prog->jited;
	state->exception_boundary = prog->aux->exception_boundary;
	state->insn_cnt = prog->len;
	state->insnsi_copy = kmemdup(prog->insnsi,
				     array_size(prog->len,
						sizeof(*prog->insnsi)),
				     GFP_KERNEL_ACCOUNT);
}

static void
bpf_jit_recompile_snapshot_free(struct bpf_jit_recompile_rollback_state *state)
{
	u32 i;

	if (!state->prog_states)
		goto out_reset;

	for (i = 0; i < state->prog_state_cnt; i++)
		kfree(state->prog_states[i].insnsi_copy);
	kfree(state->prog_states);
out_reset:
	state->prog_states = NULL;
	state->prog_state_cnt = 0;
	state->main_aux = NULL;
}

static void
bpf_jit_recompile_restore_prog_state(const struct bpf_jit_recompile_prog_state *state)
{
	struct bpf_prog *prog = state->prog;

	if (prog->aux->jit_data && prog->aux->jit_data != state->jit_data)
		bpf_jit_recompile_abort(prog);

	if (state->insnsi_copy)
		memcpy(prog->insnsi, state->insnsi_copy,
		       array_size(state->insn_cnt, sizeof(*prog->insnsi)));

	prog->bpf_func = state->bpf_func;
	prog->aux->priv_stack_ptr = state->priv_stack_ptr;
	prog->aux->extable = state->extable;
	prog->aux->jit_data = state->jit_data;
	prog->jited_len = state->jited_len;
	prog->aux->num_exentries = state->num_exentries;
	prog->jited = state->jited;
	prog->aux->exception_boundary = state->exception_boundary;
	bpf_jit_recompile_reset_prog_aux(prog);
}

static int
bpf_jit_recompile_snapshot(struct bpf_prog *prog,
			   struct bpf_jit_recompile_rollback_state *state)
{
	struct bpf_prog_aux *main_aux = bpf_prog_main_aux(prog);
	u32 real_func_cnt = main_aux->real_func_cnt ? : main_aux->func_cnt;
	u32 cnt = 1;
	u32 i = 0;

	if (main_aux->func_cnt && main_aux->func)
		cnt += real_func_cnt;

	state->prog_states = kcalloc(cnt, sizeof(*state->prog_states),
				      GFP_KERNEL_ACCOUNT);
	if (!state->prog_states)
		return -ENOMEM;

	state->main_aux = main_aux;
	state->bpf_exception_cb = main_aux->bpf_exception_cb;
	state->prog_state_cnt = cnt;
	bpf_jit_recompile_save_prog_state(&state->prog_states[i++], prog);
	if (!state->prog_states[0].insnsi_copy)
		goto err_restore;

	if (!(main_aux->func_cnt && main_aux->func))
		return 0;

	for (; i < cnt; i++) {
		if (!main_aux->func[i - 1])
			goto err_restore;
		bpf_jit_recompile_save_prog_state(&state->prog_states[i],
						  main_aux->func[i - 1]);
		if (!state->prog_states[i].insnsi_copy)
			goto err_restore;
	}

	return 0;

err_restore:
	state->prog_state_cnt = i;
	bpf_jit_recompile_snapshot_free(state);
	return -ENOMEM;
}

static void
bpf_jit_recompile_restore(struct bpf_jit_recompile_rollback_state *state)
{
	u32 i;

	if (!state->prog_states)
		return;

	for (i = 0; i < state->prog_state_cnt; i++)
		bpf_jit_recompile_restore_prog_state(&state->prog_states[i]);

	if (state->main_aux)
		state->main_aux->bpf_exception_cb = state->bpf_exception_cb;
}

static bool
bpf_jit_recompile_stage_ok(const struct bpf_prog *prog,
			   bpf_func_t old_bpf_func,
			   bool final_pass)
{
	if (!prog->jited || !prog->bpf_func)
		return false;
	if (prog->bpf_func != old_bpf_func)
		return false;
	if (!bpf_jit_recompile_staged_func(prog))
		return false;
	if (final_pass && !bpf_jit_recompile_has_staged_image(prog))
		return false;
	if (bpf_jit_recompile_staged_num_exentries(prog) &&
	    !bpf_jit_recompile_staged_extable(prog))
		return false;

	return true;
}

static void
bpf_jit_recompile_shadow_ksym_add(struct bpf_prog *prog,
				  bpf_func_t new_bpf_func, u32 new_len,
				  struct exception_table_entry *extable,
				  u32 num_exentries,
				  u32 fp_start, u32 fp_end)
{
	struct bpf_ksym *shadow = &prog->aux->jit_recompile_ksym;

	if (!prog->aux->ksym.prog || !new_bpf_func || !new_len)
		return;

	memset(shadow, 0, sizeof(*shadow));
	INIT_LIST_HEAD_RCU(&shadow->lnode);
	shadow->start = (unsigned long)new_bpf_func;
	shadow->end = (unsigned long)new_bpf_func + new_len;
	strscpy(shadow->name, prog->aux->ksym.name, KSYM_NAME_LEN);
	shadow->prog = prog->aux->ksym.prog;
	shadow->owner = prog;
	shadow->extable = extable;
	shadow->num_exentries = num_exentries;
	shadow->fp_start = fp_start;
	shadow->fp_end = fp_end;
	bpf_ksym_add(shadow);
}

static void bpf_jit_recompile_shadow_ksym_del(struct bpf_prog *prog)
{
	if (!list_empty(&prog->aux->jit_recompile_ksym.lnode))
		bpf_ksym_del(&prog->aux->jit_recompile_ksym);
}

/* ================================================================
 * Shared helpers
 * ================================================================ */

static bool bpf_jit_directives_valid_memfd(struct file *file)
{
	int seals;

	seals = memfd_fcntl(file, F_GET_SEALS, 0);
	if (seals < 0)
		return false;

	return (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) ==
	       (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK);
}

static bool bpf_jit_is_cmov_cond_jump(const struct bpf_insn *insn)
{
	u8 cls = BPF_CLASS(insn->code);

	if (cls != BPF_JMP && cls != BPF_JMP32)
		return false;
	if (BPF_SRC(insn->code) != BPF_X && BPF_SRC(insn->code) != BPF_K)
		return false;

	switch (BPF_OP(insn->code)) {
	case BPF_JEQ:
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JLT:
	case BPF_JGE:
	case BPF_JLE:
	case BPF_JSGT:
	case BPF_JSLT:
	case BPF_JSGE:
	case BPF_JSLE:
		return true;
	default:
		return false;
	}
}

static bool bpf_jit_is_simple_mov(const struct bpf_insn *insn)
{
	u8 cls = BPF_CLASS(insn->code);

	if ((cls != BPF_ALU && cls != BPF_ALU64) || BPF_OP(insn->code) != BPF_MOV)
		return false;
	if (insn->off != 0)
		return false;

	switch (BPF_SRC(insn->code)) {
	case BPF_X:
		return insn->imm == 0;
	case BPF_K:
		return insn->src_reg == 0;
	default:
		return false;
	}
}

static bool bpf_jit_cmov_select_match_diamond(const struct bpf_insn *insns,
					      u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *jmp_insn, *fallthrough_insn, *ja_insn, *target_insn;
	u8 mov_cls;

	if (idx + 3 >= insn_cnt)
		return false;

	jmp_insn = &insns[idx];
	fallthrough_insn = &insns[idx + 1];
	ja_insn = &insns[idx + 2];
	target_insn = &insns[idx + 3];

	if (!bpf_jit_is_cmov_cond_jump(jmp_insn) ||
	    bpf_jmp_offset((struct bpf_insn *)jmp_insn) != 2)
		return false;
	if (!bpf_jit_is_simple_mov(fallthrough_insn) ||
	    !bpf_jit_is_simple_mov(target_insn))
		return false;
	if (ja_insn->code != (BPF_JMP | BPF_JA) || ja_insn->off != 1 ||
	    ja_insn->imm != 0 || ja_insn->dst_reg || ja_insn->src_reg)
		return false;
	if (fallthrough_insn->dst_reg != target_insn->dst_reg)
		return false;

	mov_cls = BPF_CLASS(fallthrough_insn->code);
	if (mov_cls != BPF_CLASS(target_insn->code))
		return false;

	if (BPF_CLASS(jmp_insn->code) == BPF_JMP)
		return mov_cls == BPF_ALU64;

	return mov_cls == BPF_ALU;
}

static bool bpf_jit_cmov_select_match_compact(const struct bpf_insn *insns,
					      u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *default_insn, *jmp_insn, *override_insn;
	u8 mov_cls;

	if (!idx || idx + 1 >= insn_cnt)
		return false;

	default_insn = &insns[idx - 1];
	jmp_insn = &insns[idx];
	override_insn = &insns[idx + 1];

	if (!bpf_jit_is_simple_mov(default_insn) ||
	    !bpf_jit_is_simple_mov(override_insn))
		return false;
	if (!bpf_jit_is_cmov_cond_jump(jmp_insn) ||
	    bpf_jmp_offset((struct bpf_insn *)jmp_insn) != 1)
		return false;
	if (default_insn->dst_reg != override_insn->dst_reg)
		return false;

	mov_cls = BPF_CLASS(default_insn->code);
	if (mov_cls != BPF_CLASS(override_insn->code))
		return false;

	if (BPF_CLASS(jmp_insn->code) == BPF_JMP)
		return mov_cls == BPF_ALU64;

	return mov_cls == BPF_ALU;
}

static bool bpf_pseudo_call_insn(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}
/* ================================================================
 * BPF_PROG_JIT_RECOMPILE policy framework (v5 only)
 * ================================================================ */

static void bpf_jit_rule_release(struct bpf_jit_rule *rule)
{
	if (!rule)
		return;

	if (rule->canonical_form == BPF_JIT_CF_BRANCH_FLIP) {
		kfree((void *)(long)
		      rule->params.params[BPF_JIT_BFLIP_PARAM_BODY_A_PTR].value);
		kfree((void *)(long)
		      rule->params.params[BPF_JIT_BFLIP_PARAM_BODY_B_PTR].value);
	}

	memset(&rule->params, 0, sizeof(rule->params));
}

void bpf_jit_free_policy(struct bpf_jit_policy *policy)
{
	u32 i;

	if (!policy)
		return;

	for (i = 0; i < policy->rule_cnt; i++)
		bpf_jit_rule_release(&policy->rules[i]);
	kvfree(policy->blob);
	kvfree(policy);
}

static int rule_cmp(const void *a, const void *b)
{
	const struct bpf_jit_rule *ra = a;
	const struct bpf_jit_rule *rb = b;

	if (ra->site_start < rb->site_start)
		return -1;
	if (ra->site_start > rb->site_start)
		return 1;
	if (ra->user_index < rb->user_index)
		return -1;
	if (ra->user_index > rb->user_index)
		return 1;
	return 0;
}

static bool bpf_jit_site_range_valid(u32 site_start, u32 site_len,
				     u32 insn_cnt, u32 *site_end)
{
	u32 end;

	if (check_add_overflow(site_start, site_len, &end))
		return false;
	if (end > insn_cnt)
		return false;

	if (site_end)
		*site_end = end;

	return true;
}

/**
 * bpf_jit_has_interior_edge - check if any jump from outside targets inside a pattern
 * @insns:      full BPF instruction array
 * @insn_cnt:   number of instructions
 * @site_start: first instruction index of the pattern (inclusive)
 * @site_len:   number of instructions in the pattern
 *
 * An "interior edge" is a jump whose source is OUTSIDE [site_start,
 * site_start+site_len) and whose target falls STRICTLY INSIDE the same
 * range, i.e. target > site_start && target < site_start+site_len.
 *
 * When such a jump exists the cmov transformation would corrupt the jump's
 * target address (addrs[] entries shift), so the rule must be rejected.
 */
static bool bpf_jit_has_interior_edge(const struct bpf_insn *insns,
				      u32 insn_cnt,
				      u32 site_start, u32 site_len)
{
	u32 site_end;
	u32 i;

	if (!bpf_jit_site_range_valid(site_start, site_len, insn_cnt, &site_end))
		return true;

	for (i = 0; i < insn_cnt; i++) {
		u8 code = insns[i].code;
		u8 cls  = BPF_CLASS(code);
		u8 op;
		s32 target;

		/* Only care about jump class instructions */
		if (cls != BPF_JMP && cls != BPF_JMP32)
			continue;

		op = BPF_OP(code);

		/* EXIT and CALL do not branch to an instruction offset */
		if (op == BPF_EXIT || op == BPF_CALL)
			continue;

		/* Compute jump target (0-based absolute index) */
		if (op == BPF_JA) {
			if (cls == BPF_JMP)
				target = (s32)i + 1 + (s32)insns[i].off;
			else /* BPF_JMP32 JA encodes offset in imm */
				target = (s32)i + 1 + (s32)insns[i].imm;
		} else {
			target = (s32)i + 1 + (s32)insns[i].off;
		}

		if (target < 0 || (u32)target >= insn_cnt)
			continue;

		/*
		 * Check: source is OUTSIDE the pattern AND target is
		 * STRICTLY INTERIOR (not the first instruction, which is
		 * the canonical entry point and is fine).
		 */
		if ((i < site_start || i >= site_end) &&
		    (u32)target > site_start && (u32)target < site_end)
			return true;
	}

	return false;
}

struct bpf_jit_wide_mem_shape {
	u8 dst_reg;
	u8 base_reg;
	s16 base_off;
	u8 width;
	bool big_endian;
};

struct bpf_jit_cond_select_shape {
	u8 dst_reg;
	u8 cond_op;
	u8 cond_a;
	struct bpf_jit_binding_value cond_b;
	struct bpf_jit_binding_value true_val;
	struct bpf_jit_binding_value false_val;
	u8 width;
};

static void bpf_jit_param_set_reg(
	struct bpf_jit_canonical_params *params, u8 param, u8 reg)
{
	params->params[param].type = BPF_JIT_BIND_VAL_REG;
	params->params[param].value = reg;
}

static void bpf_jit_param_set_imm(
	struct bpf_jit_canonical_params *params, u8 param, s64 imm)
{
	params->params[param].type = BPF_JIT_BIND_VAL_IMM;
	params->params[param].value = imm;
}

static void bpf_jit_param_set_ptr(struct bpf_jit_canonical_params *params,
				  u8 param, const void *ptr)
{
	bpf_jit_param_set_imm(params, param, (long)ptr);
}

static void bpf_jit_param_set_value(
	struct bpf_jit_canonical_params *params, u8 param,
	const struct bpf_jit_binding_value *value)
{
	if (value->type == BPF_JIT_BIND_VAL_REG)
		bpf_jit_param_set_reg(params, param, value->value);
	else
		bpf_jit_param_set_imm(params, param, value->value);
}

static void bpf_jit_cond_select_get_mov_value(
	const struct bpf_insn *mov_insn,
	struct bpf_jit_binding_value *value)
{
	if (BPF_SRC(mov_insn->code) == BPF_X) {
		value->type = BPF_JIT_BIND_VAL_REG;
		value->value = mov_insn->src_reg;
	} else {
		value->type = BPF_JIT_BIND_VAL_IMM;
		value->value = mov_insn->imm;
	}
}

static bool bpf_jit_cmov_select_match_guarded_update(const struct bpf_insn *insns,
						     u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *jmp_insn, *update_insn;
	u8 mov_cls;

	if (idx + 1 >= insn_cnt)
		return false;

	jmp_insn = &insns[idx];
	update_insn = &insns[idx + 1];

	if (!bpf_jit_is_cmov_cond_jump(jmp_insn) ||
	    bpf_jmp_offset((struct bpf_insn *)jmp_insn) != 1)
		return false;
	if (!bpf_jit_is_simple_mov(update_insn))
		return false;

	mov_cls = BPF_CLASS(update_insn->code);
	if (BPF_CLASS(jmp_insn->code) == BPF_JMP)
		return mov_cls == BPF_ALU64;

	return mov_cls == BPF_ALU;
}

static bool bpf_jit_parse_cond_select_shape(
	const struct bpf_insn *insns,
	u32 insn_cnt,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_cond_select_shape *shape)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *jmp_insn, *true_insn, *false_insn;

	if (!shape || !bpf_jit_site_range_valid(idx, rule->site_len, insn_cnt, NULL))
		return false;

	switch (rule->site_len) {
	case 2:
		if (!bpf_jit_cmov_select_match_guarded_update(insns, insn_cnt, idx))
			return false;

		jmp_insn = &insns[idx];
		false_insn = &insns[idx + 1];
		shape->dst_reg = false_insn->dst_reg;
		shape->cond_op = BPF_OP(jmp_insn->code);
		shape->cond_a = jmp_insn->dst_reg;
		shape->cond_b.type = BPF_SRC(jmp_insn->code) == BPF_X ?
			BPF_JIT_BIND_VAL_REG : BPF_JIT_BIND_VAL_IMM;
		shape->cond_b.value = BPF_SRC(jmp_insn->code) == BPF_X ?
			jmp_insn->src_reg : jmp_insn->imm;
		shape->true_val.type = BPF_JIT_BIND_VAL_REG;
		shape->true_val.value = false_insn->dst_reg;
		bpf_jit_cond_select_get_mov_value(false_insn, &shape->false_val);
		shape->width = BPF_CLASS(false_insn->code) == BPF_ALU64 ? 64 : 32;
		return true;

	case 3:
		/* Compact: mov_default, jcc+1, mov_override. */
		if (!bpf_jit_cmov_select_match_compact(insns, insn_cnt, idx + 1))
			return false;

		true_insn = &insns[idx];
		jmp_insn = &insns[idx + 1];
		false_insn = &insns[idx + 2];
		break;

	case 4:
		/* Diamond: jcc+2, mov_false, ja+1, mov_true. */
		if (!bpf_jit_cmov_select_match_diamond(insns, insn_cnt, idx))
			return false;

		jmp_insn = &insns[idx];
		false_insn = &insns[idx + 1];
		true_insn = &insns[idx + 3];
		break;

	default:
		return false;
	}

	shape->dst_reg = true_insn->dst_reg;
	shape->cond_op = BPF_OP(jmp_insn->code);
	shape->cond_a = jmp_insn->dst_reg;
	shape->cond_b.type = BPF_SRC(jmp_insn->code) == BPF_X ?
		BPF_JIT_BIND_VAL_REG : BPF_JIT_BIND_VAL_IMM;
	shape->cond_b.value = BPF_SRC(jmp_insn->code) == BPF_X ?
		jmp_insn->src_reg : jmp_insn->imm;
	bpf_jit_cond_select_get_mov_value(true_insn, &shape->true_val);
	bpf_jit_cond_select_get_mov_value(false_insn, &shape->false_val);
	shape->width = BPF_CLASS(true_insn->code) == BPF_ALU64 ? 64 : 32;

	return true;
}

static void bpf_jit_cond_select_fill_params(
	struct bpf_jit_canonical_params *params,
	const struct bpf_jit_cond_select_shape *shape)
{
	memset(params, 0, sizeof(*params));
	bpf_jit_param_set_reg(params, BPF_JIT_SEL_PARAM_DST_REG,
			      shape->dst_reg);
	bpf_jit_param_set_imm(params, BPF_JIT_SEL_PARAM_COND_OP,
			      shape->cond_op);
	bpf_jit_param_set_reg(params, BPF_JIT_SEL_PARAM_COND_A,
			      shape->cond_a);
	bpf_jit_param_set_value(params, BPF_JIT_SEL_PARAM_COND_B,
				&shape->cond_b);
	bpf_jit_param_set_value(params, BPF_JIT_SEL_PARAM_TRUE_VAL,
				&shape->true_val);
	bpf_jit_param_set_value(params, BPF_JIT_SEL_PARAM_FALSE_VAL,
				&shape->false_val);
	bpf_jit_param_set_imm(params, BPF_JIT_SEL_PARAM_WIDTH,
			      shape->width);
}

/**
 * bpf_jit_validate_cond_select_rule - validate a COND_SELECT rule against prog
 *
 * Accept the exact BPF shapes that x86 can lower today:
 *   - site_len=2: guarded update (jcc+1, mov dst, src/imm)
 *   - site_len=3: compact select (mov_default, jcc+1, mov_override)
 *   - site_len=4: diamond select (jcc+2, mov_false, ja+1, mov_true)
 *
 * On success, normalize rule params from the actual site so emitters can
 * consume a complete canonical description without trusting user bindings.
 */
static bool
bpf_jit_validate_cond_select_rule(const struct bpf_insn *insns,
				      u32 insn_cnt,
				      const struct bpf_jit_rule *rule,
				      struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_cond_select_shape shape;

	if (!bpf_jit_parse_cond_select_shape(insns, insn_cnt, rule, &shape))
		return false;

	if (params)
		bpf_jit_cond_select_fill_params(params, &shape);

	return true;
}

static bool bpf_jit_parse_wide_mem_shape(const struct bpf_insn *insns,
					 u32 insn_cnt, u32 idx,
					 u32 site_len,
					 struct bpf_jit_wide_mem_shape *shape)
{
	const struct bpf_insn *first;
	s16 offsets[8];
	u8 shifts[8];
	u32 pos, end, count;
	s16 min_off, max_off;
	u32 i, j;
	bool little_endian = true;
	bool big_endian = true;

	if (!bpf_jit_site_range_valid(idx, site_len, insn_cnt, NULL) ||
	    site_len < 4)
		return false;

	first = &insns[idx];
	if (first->code != (BPF_LDX | BPF_MEM | BPF_B))
		return false;

	offsets[0] = first->off;
	shifts[0] = 0;
	count = 1;
	pos = idx + 1;
	end = idx + site_len;

	if (pos < end &&
	    insns[pos].code == (BPF_ALU64 | BPF_LSH | BPF_K) &&
	    insns[pos].dst_reg == first->dst_reg &&
	    insns[pos].off == 0 &&
	    insns[pos].imm > 0 &&
	    insns[pos].imm < 64 &&
	    (insns[pos].imm % 8) == 0) {
		shifts[0] = (u8)insns[pos].imm;
		pos++;
	}

	while (pos < end) {
		const struct bpf_insn *load_insn = &insns[pos];
		const struct bpf_insn *or_insn;
		u32 next = pos + 1;
		u8 shift_imm = 0;

		if (count == ARRAY_SIZE(offsets))
			return false;
		if (load_insn->code != (BPF_LDX | BPF_MEM | BPF_B) ||
		    load_insn->src_reg != first->src_reg ||
		    load_insn->dst_reg == first->dst_reg)
			return false;

		if (next < end &&
		    insns[next].code == (BPF_ALU64 | BPF_LSH | BPF_K) &&
		    insns[next].dst_reg == load_insn->dst_reg &&
		    insns[next].off == 0 &&
		    insns[next].imm > 0 &&
		    insns[next].imm < 64 &&
		    (insns[next].imm % 8) == 0) {
			shift_imm = (u8)insns[next].imm;
			next++;
		}

		if (next >= end)
			return false;

		or_insn = &insns[next];
		if (or_insn->code != (BPF_ALU64 | BPF_OR | BPF_X) ||
		    or_insn->dst_reg != first->dst_reg ||
		    or_insn->src_reg != load_insn->dst_reg)
			return false;

		offsets[count] = load_insn->off;
		shifts[count] = shift_imm;
		count++;
		pos = next + 1;
	}

	if (count < 2)
		return false;

	min_off = offsets[0];
	max_off = offsets[0];
	for (i = 0; i < count; i++) {
		min_off = min(min_off, offsets[i]);
		max_off = max(max_off, offsets[i]);
		for (j = i + 1; j < count; j++) {
			if (offsets[i] == offsets[j])
				return false;
		}
	}

	if (max_off - min_off + 1 != count)
		return false;

	for (i = 0; i < count; i++) {
		u8 le_shift = (u8)((offsets[i] - min_off) * 8);
		u8 be_shift = (u8)((max_off - offsets[i]) * 8);

		little_endian &= shifts[i] == le_shift;
		big_endian &= shifts[i] == be_shift;
	}

	if (!little_endian && !big_endian)
		return false;

	if (shape) {
		shape->dst_reg = first->dst_reg;
		shape->base_reg = first->src_reg;
		shape->base_off = min_off;
		shape->width = (u8)count;
		shape->big_endian = !little_endian && big_endian;
	}

	return true;
}

/**
 * bpf_jit_validate_wide_mem_rule - validate a WIDE_MEM rule against prog
 *
 * Supports two patterns:
 *   1. Low-byte-first: ldxb dst, [base+off]; ldxb tmp, [base+off+1]; lsh tmp, 8; or dst, tmp; ...
 *   2. High-byte-first (clang): ldxb tmp, [base+off+1]; lsh tmp, 8; ldxb dst, [base+off]; or tmp, dst
 */
static bool
bpf_jit_validate_wide_mem_rule(const struct bpf_insn *insns,
			       u32 insn_cnt,
			       const struct bpf_jit_rule *rule,
			       struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_wide_mem_shape shape;
	s64 encoded_width;

	if (!bpf_jit_parse_wide_mem_shape(insns, insn_cnt, rule->site_start,
					  rule->site_len, &shape))
		return false;

	encoded_width = shape.width |
			(shape.big_endian ? BPF_JIT_WMEM_F_BIG_ENDIAN : 0);
	if (rule->site_len != 3 * shape.width - 2)
		return false;

	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_WMEM_PARAM_DST_REG,
				      shape.dst_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_WMEM_PARAM_BASE_REG,
				      shape.base_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_WMEM_PARAM_BASE_OFF,
				      shape.base_off);
		bpf_jit_param_set_imm(params, BPF_JIT_WMEM_PARAM_WIDTH,
				      encoded_width);
	}

	return true;
}

struct bpf_jit_rotate_shape {
	u8 dst_reg;
	u8 src_reg;
	u8 width;
	u8 amount;
};

struct bpf_jit_rotate_spec {
	u8 site_len;
	u8 width;		/* 0 => infer from the first MOV class */
	u8 insn_class;		/* 0 => infer from the first MOV class */
	bool masked;
	bool two_copy;
	bool allow_shift_swap;
};

static bool bpf_jit_rotate_match_copy(const struct bpf_insn *insn,
				      u8 insn_class)
{
	return BPF_CLASS(insn->code) == insn_class &&
	       BPF_OP(insn->code) == BPF_MOV &&
	       BPF_SRC(insn->code) == BPF_X &&
	       !insn->off &&
	       !insn->imm;
}

static bool bpf_jit_rotate_match_shift(const struct bpf_insn *insn,
				       u8 insn_class, u8 op, u8 dst_reg,
				       u32 width, u32 *amount)
{
	u32 imm = (u32)insn->imm;

	if (BPF_CLASS(insn->code) != insn_class ||
	    BPF_OP(insn->code) != op ||
	    BPF_SRC(insn->code) != BPF_K)
		return false;
	if (insn->off != 0 || insn->dst_reg != dst_reg)
		return false;
	if (!imm || imm >= width)
		return false;

	*amount = imm;
	return true;
}

/**
 * bpf_jit_validate_rotate_5insn_masked - validate a 5-insn masked 32-bit rotate
 *
 * clang sometimes emits a 5-insn variant when the second MOV is eliminated:
 *   [0] mov64  tmp, src       (copy for mask+rsh path)
 *   [1] and64  tmp, mask      (AND_K only)
 *   [2,3] rsh64 tmp, (32-N) + lsh64 src, N  (either order)
 *   [4] or64   src, tmp       (combine back into src)
 *
 * This is always a 32-bit rotate (N + rsh_amount == 32).
 */
static bool bpf_jit_rotate_mask_matches(u32 rot_amount, s32 imm)
{
	u32 low_mask;
	u32 high_mask;
	u32 mask = (u32)imm;

	if (!rot_amount || rot_amount >= 32)
		return false;

	low_mask = (1U << (32 - rot_amount)) - 1;
	high_mask = ~low_mask;

	return mask == low_mask || mask == high_mask;
}
static bool
bpf_jit_rotate_validate_common(const struct bpf_insn *insns, u32 idx,
			       const struct bpf_jit_rotate_spec *spec,
			       struct bpf_jit_rotate_shape *shape)
{
	const struct bpf_insn *mov1 = &insns[idx];
	const struct bpf_insn *and_insn = NULL;
	const struct bpf_insn *mov2 = NULL;
	const struct bpf_insn *or_insn = &insns[idx + spec->site_len - 1];
	const struct bpf_insn *shift1;
	const struct bpf_insn *shift2;
	const struct bpf_insn *lsh_insn;
	const struct bpf_insn *rsh_insn;
	u8 insn_class, dst_reg;
	u32 width, rot_amount, rsh_amount;

	if (spec->masked)
		and_insn = &insns[idx + 1];
	if (spec->two_copy)
		mov2 = &insns[idx + (spec->masked ? 3 : 2)];

	if (!bpf_jit_rotate_match_copy(mov1,
				       spec->insn_class ?: BPF_CLASS(mov1->code)))
		return false;
	if (mov1->dst_reg == mov1->src_reg)
		return false;

	if (spec->insn_class) {
		insn_class = spec->insn_class;
		width = spec->width;
	} else if (BPF_CLASS(mov1->code) == BPF_ALU64) {
		insn_class = BPF_ALU64;
		width = 64;
	} else if (BPF_CLASS(mov1->code) == BPF_ALU) {
		insn_class = BPF_ALU;
		width = 32;
	} else {
		return false;
	}

	if (spec->masked) {
		if (BPF_CLASS(and_insn->code) != insn_class ||
		    BPF_OP(and_insn->code) != BPF_AND ||
		    BPF_SRC(and_insn->code) != BPF_K)
			return false;
		if (and_insn->off != 0 || and_insn->dst_reg != mov1->dst_reg)
			return false;
	}

	if (spec->two_copy) {
		if (!bpf_jit_rotate_match_copy(mov2, insn_class))
			return false;
		if (mov2->src_reg != mov1->src_reg ||
		    mov2->dst_reg == mov1->dst_reg)
			return false;
		dst_reg = mov2->dst_reg;
	} else {
		dst_reg = mov1->src_reg;
	}

	if (spec->allow_shift_swap) {
		shift1 = &insns[idx + (spec->masked ? 2 : 1)];
		shift2 = &insns[idx + (spec->masked ? 3 : 2)];

		if (BPF_OP(shift1->code) == BPF_LSH && BPF_OP(shift2->code) == BPF_RSH) {
			lsh_insn = shift1;
			rsh_insn = shift2;
		} else if (BPF_OP(shift1->code) == BPF_RSH &&
			   BPF_OP(shift2->code) == BPF_LSH) {
			rsh_insn = shift1;
			lsh_insn = shift2;
		} else {
			return false;
		}
	} else {
		rsh_insn = &insns[idx + (spec->masked ? 2 : 1)];
		lsh_insn = &insns[idx + (spec->masked ? 4 : 3)];
	}

	if (!bpf_jit_rotate_match_shift(rsh_insn, insn_class, BPF_RSH,
					mov1->dst_reg, width, &rsh_amount) ||
	    !bpf_jit_rotate_match_shift(lsh_insn, insn_class, BPF_LSH,
					dst_reg, width, &rot_amount))
		return false;
	if (rot_amount + rsh_amount != width)
		return false;

	if (BPF_CLASS(or_insn->code) != insn_class ||
	    BPF_OP(or_insn->code) != BPF_OR ||
	    BPF_SRC(or_insn->code) != BPF_X)
		return false;
	if (or_insn->off != 0 || or_insn->imm != 0)
		return false;
	if (or_insn->dst_reg != dst_reg || or_insn->src_reg != mov1->dst_reg)
		return false;

	if (spec->masked &&
	    !bpf_jit_rotate_mask_matches(rot_amount, and_insn->imm))
		return false;

	if (shape) {
		shape->dst_reg = dst_reg;
		shape->src_reg = mov1->src_reg;
		shape->width = (u8)width;
		shape->amount = (u8)rot_amount;
	}

	return true;
}

/**
 * bpf_jit_validate_rotate_rule - validate a ROTATE rule against prog
 *
 * Supports four source shapes that all normalize to the same
 * dst/src/amount/width canonical parameter set:
 *   site_len==4: classic or commuted in-place rotate
 *   site_len==5: 64-bit two-copy rotate
 *   site_len==5: masked 32-bit in-place rotate
 *   site_len==6: masked 32-bit two-copy rotate
 */
static bool
bpf_jit_validate_rotate_rule(const struct bpf_insn *insns,
			     u32 insn_cnt,
			     const struct bpf_jit_rule *rule,
			     struct bpf_jit_canonical_params *params)
{
	static const struct bpf_jit_rotate_spec rotate_specs[] = {
		{ .site_len = 4, .allow_shift_swap = true },
		{ .site_len = 5, .width = 64, .insn_class = BPF_ALU64,
		  .two_copy = true },
		{ .site_len = 5, .width = 32, .insn_class = BPF_ALU64,
		  .masked = true, .allow_shift_swap = true },
		{ .site_len = 6, .width = 32, .insn_class = BPF_ALU64,
		  .masked = true, .two_copy = true },
	};
	struct bpf_jit_rotate_shape shape;
	u32 i;

	(void)insn_cnt;

	for (i = 0; i < ARRAY_SIZE(rotate_specs); i++) {
		if (rotate_specs[i].site_len != rule->site_len)
			continue;
		if (bpf_jit_rotate_validate_common(insns, rule->site_start,
						   &rotate_specs[i], &shape))
			goto out_fill;
	}

	return false;

out_fill:
	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_ROT_PARAM_DST_REG,
				      shape.dst_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_ROT_PARAM_SRC_REG,
				      shape.src_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_ROT_PARAM_AMOUNT,
				      shape.amount);
		bpf_jit_param_set_imm(params, BPF_JIT_ROT_PARAM_WIDTH,
				      shape.width);
	}

	return true;
}

struct bpf_jit_bitfield_extract_desc {
	u8 dst_reg;
	u8 src_reg;
	s32 shift;
	s32 mask;
	u8 width;
	bool mask_first;
};

static bool bpf_jit_parse_bitfield_extract_site(
	const struct bpf_insn *insns,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_bitfield_extract_desc *desc)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *mov_insn = NULL;
	const struct bpf_insn *first, *second;
	u8 mov_opcode, rsh_opcode, and_opcode;
	u8 dst_reg, src_reg, width;
	s32 shift, mask;
	bool mask_first;

	if (rule->site_len == 3) {
		mov_insn = &insns[idx];
		first = &insns[idx + 1];
		second = &insns[idx + 2];
	} else if (rule->site_len == 2) {
		first = &insns[idx];
		second = &insns[idx + 1];
	} else {
		return false;
	}

	switch (first->code) {
	case BPF_ALU64 | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
		width = 64;
		mov_opcode = BPF_ALU64 | BPF_MOV | BPF_X;
		rsh_opcode = BPF_ALU64 | BPF_RSH | BPF_K;
		and_opcode = BPF_ALU64 | BPF_AND | BPF_K;
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
		width = 32;
		mov_opcode = BPF_ALU | BPF_MOV | BPF_X;
		rsh_opcode = BPF_ALU | BPF_RSH | BPF_K;
		and_opcode = BPF_ALU | BPF_AND | BPF_K;
		break;
	default:
		return false;
	}

	if (mov_insn) {
		if (mov_insn->code != mov_opcode || mov_insn->off || mov_insn->imm)
			return false;
		dst_reg = mov_insn->dst_reg;
		src_reg = mov_insn->src_reg;
		if (first->dst_reg != dst_reg || second->dst_reg != dst_reg)
			return false;
	} else {
		dst_reg = first->dst_reg;
		src_reg = dst_reg;
		if (second->dst_reg != dst_reg)
			return false;
	}

	if (first->off || second->off)
		return false;

	if (first->code == rsh_opcode && second->code == and_opcode) {
		shift = first->imm;
		mask = second->imm;
		mask_first = false;
	} else if (first->code == and_opcode && second->code == rsh_opcode) {
		shift = second->imm;
		mask = first->imm;
		mask_first = true;
	} else {
		return false;
	}

	if (shift < 0 || shift >= width)
		return false;

	if (desc) {
		desc->dst_reg = dst_reg;
		desc->src_reg = src_reg;
		desc->shift = shift;
		desc->mask = mask;
		desc->width = width;
		desc->mask_first = mask_first;
	}

	return true;
}

static bool
bpf_jit_validate_bitfield_extract_rule(const struct bpf_insn *insns,
				       u32 insn_cnt,
				       const struct bpf_jit_rule *rule,
				       struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_bitfield_extract_desc desc;

	if (!bpf_jit_parse_bitfield_extract_site(insns, rule, &desc))
		return false;

	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_BFX_PARAM_DST_REG,
				      desc.dst_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_BFX_PARAM_SRC_REG,
				      desc.src_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_BFX_PARAM_SHIFT,
				      desc.shift);
		bpf_jit_param_set_imm(params, BPF_JIT_BFX_PARAM_MASK, desc.mask);
		bpf_jit_param_set_imm(params, BPF_JIT_BFX_PARAM_WIDTH,
				      desc.width);
		bpf_jit_param_set_imm(params, BPF_JIT_BFX_PARAM_ORDER,
				      desc.mask_first ?
				      BPF_JIT_BFX_ORDER_MASK_SHIFT :
				      BPF_JIT_BFX_ORDER_SHIFT_MASK);
	}

	return true;
}

/**
 * bpf_jit_validate_addr_calc_rule - validate an ADDR_CALC rule against prog
 *
 * Check that the BPF insn sequence at site_start matches:
 *   [0] mov   dst, idx        (copy index, reg-to-reg)
 *   [1] lsh64 dst, scale      (scale in {1,2,3} for *2, *4, *8)
 *   [2] add64 dst, base       (add base register)
 *
 * site_len must be 3.
 */
struct bpf_jit_addr_calc_shape {
	u8 dst_reg;
	u8 base_reg;
	u8 index_reg;
	u8 scale;
};

static bool bpf_jit_parse_addr_calc_shape(
	const struct bpf_insn *insns,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_addr_calc_shape *shape)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *mov_insn, *lsh_insn, *add_insn;

	if (rule->site_len != 3)
		return false;

	mov_insn = &insns[idx];
	lsh_insn = &insns[idx + 1];
	add_insn = &insns[idx + 2];

	/* [0] Must be MOV_X (reg-to-reg copy), ALU64 */
	if (mov_insn->code != (BPF_ALU64 | BPF_MOV | BPF_X))
		return false;
	if (mov_insn->off != 0 || mov_insn->imm != 0)
		return false;

	/* [1] lsh64 dst, K where K in {1, 2, 3} */
	if (lsh_insn->code != (BPF_ALU64 | BPF_LSH | BPF_K))
		return false;
	if (lsh_insn->dst_reg != mov_insn->dst_reg)
		return false;
	if (lsh_insn->imm < 1 || lsh_insn->imm > 3)
		return false;

	/* [2] add64 dst, X (register) */
	if (add_insn->code != (BPF_ALU64 | BPF_ADD | BPF_X))
		return false;
	if (add_insn->dst_reg != mov_insn->dst_reg ||
	    add_insn->off != 0 || add_insn->imm != 0)
		return false;

	if (shape) {
		shape->dst_reg = mov_insn->dst_reg;
		shape->base_reg = add_insn->src_reg;
		shape->index_reg = mov_insn->src_reg;
		shape->scale = (u8)lsh_insn->imm;
	}

	return true;
}

static bool
bpf_jit_validate_addr_calc_rule(const struct bpf_insn *insns,
				u32 insn_cnt,
				const struct bpf_jit_rule *rule,
				struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_addr_calc_shape shape;

	if (!bpf_jit_parse_addr_calc_shape(insns, rule, &shape))
		return false;

	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_ACALC_PARAM_DST_REG,
				      shape.dst_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_ACALC_PARAM_BASE_REG,
				      shape.base_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_ACALC_PARAM_INDEX_REG,
				      shape.index_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_ACALC_PARAM_SCALE,
				      shape.scale);
	}

	return true;
}

static bool bpf_jit_zero_ext_elide_is_alu32(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_ALU && BPF_OP(insn->code) != BPF_END;
}

static bool bpf_jit_zero_ext_elide_is_tail(const struct bpf_insn *insn, u8 dst_reg)
{
	if (insn_is_zext(insn))
		return insn->dst_reg == dst_reg &&
		       insn->src_reg == dst_reg &&
		       !insn->off;

	if (insn->code == (BPF_ALU64 | BPF_MOV | BPF_X)) {
		return insn->dst_reg == dst_reg &&
		       insn->src_reg == dst_reg &&
		       !insn->off &&
		       !insn->imm;
	}

	if (insn->code == (BPF_ALU64 | BPF_AND | BPF_K)) {
		return insn->dst_reg == dst_reg &&
		       !insn->off &&
		       insn->imm == -1;
	}

	return false;
}

struct bpf_jit_zero_ext_elide_shape {
	u8 code;
	u8 dst_reg;
	u8 src_reg;
	s16 off;
	s32 imm;
};

static bool bpf_jit_parse_zero_ext_elide_shape(
	const struct bpf_insn *insns,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_zero_ext_elide_shape *shape)
{
	const struct bpf_insn *alu32_insn;
	const struct bpf_insn *zext_insn;
	u32 idx = rule->site_start;

	if (rule->site_len != 2)
		return false;

	alu32_insn = &insns[idx];
	zext_insn = &insns[idx + 1];
	if (!bpf_jit_zero_ext_elide_is_alu32(alu32_insn) ||
	    !bpf_jit_zero_ext_elide_is_tail(zext_insn, alu32_insn->dst_reg))
		return false;

	if (shape) {
		shape->code = alu32_insn->code;
		shape->dst_reg = alu32_insn->dst_reg;
		shape->src_reg = alu32_insn->src_reg;
		shape->off = alu32_insn->off;
		shape->imm = alu32_insn->imm;
	}

	return true;
}

static bool
bpf_jit_validate_zero_ext_elide_rule(const struct bpf_insn *insns,
				     u32 insn_cnt,
				     const struct bpf_jit_rule *rule,
				     struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_zero_ext_elide_shape shape;

	if (!bpf_jit_parse_zero_ext_elide_shape(insns, rule, &shape))
		return false;

	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_ZEXT_PARAM_DST_REG,
				      shape.dst_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_ZEXT_PARAM_CODE,
				      shape.code);
		bpf_jit_param_set_reg(params, BPF_JIT_ZEXT_PARAM_SRC_REG,
				      shape.src_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_ZEXT_PARAM_OFF,
				      shape.off);
		bpf_jit_param_set_imm(params, BPF_JIT_ZEXT_PARAM_IMM,
				      shape.imm);
	}

	return true;
}

static s32 bpf_jit_endian_width_from_mem_opcode(u8 code)
{
	switch (code) {
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_H:
		return 16;
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_W:
		return 32;
	case BPF_LDX | BPF_MEM | BPF_DW:
	case BPF_STX | BPF_MEM | BPF_DW:
		return 64;
	default:
		return -1;
	}
}

static bool bpf_jit_endian_fusion_is_swap(const struct bpf_insn *insn, s32 width)
{
	if (insn->off || insn->src_reg || insn->imm != width)
		return false;

	if (insn->code == (BPF_ALU64 | BPF_END | BPF_FROM_LE))
		return width == 16 || width == 32 || width == 64;

	if (insn->code == (BPF_ALU | BPF_END | BPF_FROM_BE))
		return width == 16 || width == 32;

	return false;
}

struct bpf_jit_endian_fusion_shape {
	u8 data_reg;
	u8 base_reg;
	s16 offset;
	u8 width;
	u8 direction;
};

static bool bpf_jit_parse_endian_fusion_shape(
	const struct bpf_insn *insns,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_endian_fusion_shape *shape)
{
	const struct bpf_insn *first;
	const struct bpf_insn *second;
	s32 width_bits;
	u32 idx = rule->site_start;

	if (rule->site_len != 2)
		return false;

	first = &insns[idx];
	second = &insns[idx + 1];

	width_bits = bpf_jit_endian_width_from_mem_opcode(first->code);
	if (width_bits > 0 && BPF_CLASS(first->code) == BPF_LDX) {
		if (first->imm || !bpf_jit_endian_fusion_is_swap(second, width_bits))
			return false;
		if (first->dst_reg != second->dst_reg)
			return false;
		if (shape) {
			shape->data_reg = first->dst_reg;
			shape->base_reg = first->src_reg;
			shape->offset = first->off;
			shape->width = (u8)width_bits;
			shape->direction = BPF_JIT_ENDIAN_LOAD_SWAP;
		}
		return true;
	}

	width_bits = bpf_jit_endian_width_from_mem_opcode(second->code);
	if (width_bits > 0 && BPF_CLASS(second->code) == BPF_STX) {
		if (second->imm ||
		    !bpf_jit_endian_fusion_is_swap(first, width_bits))
			return false;
		if (first->dst_reg != second->src_reg)
			return false;
		if (shape) {
			shape->data_reg = first->dst_reg;
			shape->base_reg = second->dst_reg;
			shape->offset = second->off;
			shape->width = (u8)width_bits;
			shape->direction = BPF_JIT_ENDIAN_SWAP_STORE;
		}
		return true;
	}

	return false;
}

static bool
bpf_jit_validate_endian_fusion_rule(const struct bpf_insn *insns,
				    u32 insn_cnt,
				    const struct bpf_jit_rule *rule,
				    struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_endian_fusion_shape shape;

	if (!bpf_jit_parse_endian_fusion_shape(insns, rule, &shape))
		return false;

	if (params) {
		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_reg(params, BPF_JIT_ENDIAN_PARAM_DATA_REG,
				      shape.data_reg);
		bpf_jit_param_set_reg(params, BPF_JIT_ENDIAN_PARAM_BASE_REG,
				      shape.base_reg);
		bpf_jit_param_set_imm(params, BPF_JIT_ENDIAN_PARAM_OFFSET,
				      shape.offset);
		bpf_jit_param_set_imm(params, BPF_JIT_ENDIAN_PARAM_WIDTH,
				      shape.width);
		bpf_jit_param_set_imm(params, BPF_JIT_ENDIAN_PARAM_DIRECTION,
				      shape.direction);
	}

	return true;
}

static bool bpf_jit_branch_flip_body_linear(const struct bpf_insn *insns,
					    u32 start, u32 len)
{
	u32 i;

	if (!len)
		return false;

	for (i = start; i < start + len; i++) {
		u8 cls = BPF_CLASS(insns[i].code);
		u8 op = BPF_OP(insns[i].code);

		if ((cls == BPF_JMP || cls == BPF_JMP32) &&
		    op != BPF_CALL && op != BPF_EXIT)
			return false;
		if (cls == BPF_STX || cls == BPF_ST)
			return false;
		if (insns[i].code == (BPF_LD | BPF_IMM | BPF_DW))
			return false;
	}

	return true;
}

static bool bpf_jit_branch_flip_cond_op_valid(u8 op);

struct bpf_jit_branch_flip_shape {
	u8 cond_code;
	u8 cond_dst_reg;
	struct bpf_jit_binding_value cond_src;
	u32 body_a_start;
	u32 body_a_len;
	u32 body_b_start;
	u32 body_b_len;
};

static bool bpf_jit_parse_branch_flip_shape(
	const struct bpf_insn *insns,
	u32 insn_cnt,
	const struct bpf_jit_rule *rule,
	struct bpf_jit_branch_flip_shape *shape)
{
	const struct bpf_insn *jcc;
	const struct bpf_insn *ja_insn;
	u32 idx = rule->site_start;
	u32 body_a_start, body_b_start, body_a_len, body_b_len, join_target;
	u32 ja_idx;

	if (rule->site_len < 4)
		return false;

	jcc = &insns[idx];
	if ((BPF_CLASS(jcc->code) != BPF_JMP && BPF_CLASS(jcc->code) != BPF_JMP32) ||
	    !bpf_jit_branch_flip_cond_op_valid(BPF_OP(jcc->code)))
		return false;

	body_a_start = idx + 1;
	body_b_start = body_a_start + jcc->off;
	if (body_b_start <= body_a_start || body_b_start > insn_cnt)
		return false;

	ja_idx = body_b_start - 1;
	if (ja_idx <= idx || ja_idx >= insn_cnt)
		return false;
	ja_insn = &insns[ja_idx];
	if (ja_insn->code != (BPF_JMP | BPF_JA))
		return false;

	body_a_len = ja_idx - body_a_start;
	if (!body_a_len || body_a_len > 16)
		return false;

	join_target = ja_idx + 1 + ja_insn->off;
	if (join_target <= body_b_start || join_target > insn_cnt)
		return false;
	body_b_len = join_target - body_b_start;
	if (!body_b_len || body_b_len > 16)
		return false;

	if (join_target != idx + rule->site_len)
		return false;
	if (!bpf_jit_branch_flip_body_linear(insns, body_a_start, body_a_len) ||
	    !bpf_jit_branch_flip_body_linear(insns, body_b_start, body_b_len))
		return false;

	if (shape) {
		shape->cond_code = jcc->code;
		shape->cond_dst_reg = jcc->dst_reg;
		shape->cond_src.type = BPF_SRC(jcc->code) == BPF_X ?
			BPF_JIT_BIND_VAL_REG : BPF_JIT_BIND_VAL_IMM;
		shape->cond_src.value = BPF_SRC(jcc->code) == BPF_X ?
			jcc->src_reg : jcc->imm;
		shape->body_a_start = body_a_start;
		shape->body_a_len = body_a_len;
		shape->body_b_start = body_b_start;
		shape->body_b_len = body_b_len;
	}

	return true;
}

static bool
bpf_jit_validate_branch_flip_rule(const struct bpf_insn *insns,
				  u32 insn_cnt,
				  const struct bpf_jit_rule *rule,
				  struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_branch_flip_shape shape;
	struct bpf_insn *body_a_insns = NULL;
	struct bpf_insn *body_b_insns = NULL;

	if (!bpf_jit_parse_branch_flip_shape(insns, insn_cnt, rule, &shape))
		return false;

	if (params) {
		body_a_insns = kmemdup(&insns[shape.body_a_start],
				       array_size(shape.body_a_len,
						  sizeof(*body_a_insns)),
				       GFP_KERNEL_ACCOUNT);
		if (!body_a_insns)
			return false;

		body_b_insns = kmemdup(&insns[shape.body_b_start],
				       array_size(shape.body_b_len,
						  sizeof(*body_b_insns)),
				       GFP_KERNEL_ACCOUNT);
		if (!body_b_insns) {
			kfree(body_a_insns);
			return false;
		}

		memset(params, 0, sizeof(*params));
		bpf_jit_param_set_imm(params, BPF_JIT_BFLIP_PARAM_COND_CODE,
				      shape.cond_code);
		bpf_jit_param_set_reg(params, BPF_JIT_BFLIP_PARAM_COND_DST_REG,
				      shape.cond_dst_reg);
		bpf_jit_param_set_value(params, BPF_JIT_BFLIP_PARAM_COND_SRC,
					&shape.cond_src);
		bpf_jit_param_set_imm(params, BPF_JIT_BFLIP_PARAM_BODY_A_LEN,
				      shape.body_a_len);
		bpf_jit_param_set_ptr(params, BPF_JIT_BFLIP_PARAM_BODY_A_PTR,
				      body_a_insns);
		bpf_jit_param_set_imm(params, BPF_JIT_BFLIP_PARAM_BODY_B_LEN,
				      shape.body_b_len);
		bpf_jit_param_set_ptr(params, BPF_JIT_BFLIP_PARAM_BODY_B_PTR,
				      body_b_insns);
	}

	return true;
}

/**
 * bpf_jit_site_has_side_effects - reject sites containing unsafe instructions
 *
 * A rule site must be pure computation (no memory stores, helper calls, or
 * atomics).  This generic Layer-2 check runs before kind-specific validation
 * and filters out sites that would be unsafe to rewrite regardless of the
 * particular transformation.
 */
static bool bpf_jit_site_has_side_effects(const struct bpf_insn *insns,
					   u32 site_start, u32 site_len)
{
	u32 site_end;
	u32 i;

	if (check_add_overflow(site_start, site_len, &site_end))
		return true;

	for (i = site_start; i < site_end; i++) {
		u8 cls = BPF_CLASS(insns[i].code);
		u8 op  = BPF_OP(insns[i].code);

		/* Reject helper calls */
		if (cls == BPF_JMP && op == BPF_CALL)
			return true;

		/* Reject stores (BPF_STX, BPF_ST) */
		if (cls == BPF_STX || cls == BPF_ST)
			return true;
	}
	return false;
}

static bool bpf_jit_cond_op_valid(u8 op)
{
	switch (op) {
	case BPF_JEQ:
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JLT:
	case BPF_JGE:
	case BPF_JLE:
	case BPF_JSGT:
	case BPF_JSLT:
	case BPF_JSGE:
	case BPF_JSLE:
		return true;
	default:
		return false;
	}
}

static bool bpf_jit_branch_flip_cond_op_valid(u8 op)
{
	return op == BPF_JSET || bpf_jit_cond_op_valid(op);
}

struct bpf_jit_form_meta {
	const char *name;
	unsigned long native_choice_mask;
	bool allow_side_effects;
	bool (*choice_supported)(u16 native_choice);
	bool (*validate)(const struct bpf_insn *insns, u32 insn_cnt,
			 const struct bpf_jit_rule *rule,
			 struct bpf_jit_canonical_params *params);
};

static bool bpf_jit_choice_always_supported(u16 native_choice)
{
	return true;
}

static bool bpf_jit_cond_select_choice_supported(u16 native_choice)
{
#if defined(CONFIG_X86_64)
	return native_choice != BPF_JIT_SEL_CMOVCC ||
	       boot_cpu_has(X86_FEATURE_CMOV);
#else
	return true;
#endif
}

static bool bpf_jit_rotate_choice_supported(u16 native_choice)
{
#if defined(CONFIG_X86_64)
	return native_choice != BPF_JIT_ROT_RORX ||
	       boot_cpu_has(X86_FEATURE_BMI2);
#else
	return true;
#endif
}

static bool bpf_jit_endian_choice_supported(u16 native_choice)
{
#if defined(CONFIG_X86_64)
	return native_choice != BPF_JIT_ENDIAN_MOVBE ||
	       boot_cpu_has(X86_FEATURE_MOVBE);
#else
	return true;
#endif
}

static const struct bpf_jit_form_meta bpf_jit_form_meta[] = {
	[BPF_JIT_CF_ROTATE] = {
		.name = "rotate",
		.native_choice_mask = BIT(BPF_JIT_ROT_ROR) |
				      BIT(BPF_JIT_ROT_RORX),
		.choice_supported = bpf_jit_rotate_choice_supported,
		.validate = bpf_jit_validate_rotate_rule,
	},
	[BPF_JIT_CF_WIDE_MEM] = {
		.name = "wide_mem",
		.native_choice_mask = BIT(BPF_JIT_WMEM_WIDE_LOAD),
		.choice_supported = bpf_jit_choice_always_supported,
		.validate = bpf_jit_validate_wide_mem_rule,
	},
	[BPF_JIT_CF_ADDR_CALC] = {
		.name = "addr_calc",
		.native_choice_mask = BIT(BPF_JIT_ACALC_LEA),
		.choice_supported = bpf_jit_choice_always_supported,
		.validate = bpf_jit_validate_addr_calc_rule,
	},
	[BPF_JIT_CF_COND_SELECT] = {
		.name = "cond_select",
		.native_choice_mask = BIT(BPF_JIT_SEL_CMOVCC),
		.choice_supported = bpf_jit_cond_select_choice_supported,
		.validate = bpf_jit_validate_cond_select_rule,
	},
	[BPF_JIT_CF_BITFIELD_EXTRACT] = {
		.name = "bitfield_extract",
		.native_choice_mask = BIT(BPF_JIT_BFX_EXTRACT),
		.choice_supported = bpf_jit_choice_always_supported,
		.validate = bpf_jit_validate_bitfield_extract_rule,
	},
	[BPF_JIT_CF_ZERO_EXT_ELIDE] = {
		.name = "zero_ext_elide",
		.native_choice_mask = BIT(BPF_JIT_ZEXT_ELIDE),
		.choice_supported = bpf_jit_choice_always_supported,
		.validate = bpf_jit_validate_zero_ext_elide_rule,
	},
	[BPF_JIT_CF_ENDIAN_FUSION] = {
		.name = "endian_fusion",
		.native_choice_mask = BIT(BPF_JIT_ENDIAN_MOVBE),
		.allow_side_effects = true,
		.choice_supported = bpf_jit_endian_choice_supported,
		.validate = bpf_jit_validate_endian_fusion_rule,
	},
	[BPF_JIT_CF_BRANCH_FLIP] = {
		.name = "branch_flip",
		.native_choice_mask = BIT(BPF_JIT_BFLIP_FLIPPED),
		.choice_supported = bpf_jit_choice_always_supported,
		.validate = bpf_jit_validate_branch_flip_rule,
	},
};

static const struct bpf_jit_form_meta *bpf_jit_get_form_meta(u16 form)
{
	if (form >= ARRAY_SIZE(bpf_jit_form_meta) ||
	    !bpf_jit_form_meta[form].validate)
		return NULL;

	return &bpf_jit_form_meta[form];
}

static bool bpf_jit_pattern_rule_shape_valid(const struct bpf_jit_rule *rule)
{
	return rule->site_len > 0 &&
	       rule->site_len <= BPF_JIT_MAX_PATTERN_LEN &&
	       bpf_jit_get_form_meta(rule->canonical_form);
}

static bool bpf_jit_canonical_site_fail(const struct bpf_prog *prog,
					const struct bpf_jit_rule *rule,
					const struct bpf_jit_form_meta *meta)
{
	const char *msg = meta->name;

	bpf_jit_recompile_rule_log(prog, rule,
				   "%s canonical site validation failed", msg);
	pr_debug("bpf_jit: rule %u form %u site %u len %u: %s canonical site validation failed\n",
		 rule->user_index, rule->canonical_form,
		 rule->site_start, rule->site_len, msg);
	return false;
}

static bool bpf_jit_validate_canonical_site(const struct bpf_prog *prog,
					    const struct bpf_insn *insns,
					    u32 insn_cnt,
					    const struct bpf_jit_rule *rule,
					    struct bpf_jit_canonical_params *params)
{
	const struct bpf_jit_form_meta *meta;

	meta = bpf_jit_get_form_meta(rule->canonical_form);
	if (!meta || !meta->validate(insns, insn_cnt, rule, params))
		return meta ? bpf_jit_canonical_site_fail(prog, rule, meta) : false;

	return true;
}

static bool bpf_jit_validate_rule(const struct bpf_prog *prog,
				  const struct bpf_insn *insns,
				  u32 insn_cnt,
				  const struct bpf_jit_rule *rule,
				  struct bpf_jit_canonical_params *params)
{
	const struct bpf_jit_form_meta *meta;

	if (params)
		memset(params, 0, sizeof(*params));

	if (!bpf_jit_pattern_rule_shape_valid(rule)) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "invalid rule header");
		return false;
	}
	if (!bpf_jit_site_range_valid(rule->site_start, rule->site_len,
				      insn_cnt, NULL)) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "site range is out of bounds");
		return false;
	}
	meta = bpf_jit_get_form_meta(rule->canonical_form);
	if (!meta ||
	    rule->native_choice >= BITS_PER_LONG ||
	    !(meta->native_choice_mask & BIT(rule->native_choice))) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "native choice %u is invalid",
					   rule->native_choice);
		return false;
	}
	if (!meta->choice_supported(rule->native_choice)) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "native choice %u is unsupported on this CPU",
					   rule->native_choice);
		return false;
	}
	if (!meta->allow_side_effects &&
	    bpf_jit_site_has_side_effects(insns, rule->site_start,
					  rule->site_len)) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "site has side effects");
		return false;
	}
	if (!bpf_jit_validate_canonical_site(prog, insns, insn_cnt, rule,
					     params))
		return false;
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start,
				      rule->site_len)) {
		bpf_jit_recompile_rule_log(prog, rule,
					   "interior control-flow edge detected");
		return false;
	}

	return true;
}

static bool bpf_jit_rule_within_single_subprog(const struct bpf_prog *prog,
					       const struct bpf_jit_rule *rule)
{
	const struct bpf_prog_aux *main_aux;
	u32 real_func_cnt;
	u32 site_end;
	u32 i;

	if (check_add_overflow(rule->site_start, rule->site_len, &site_end))
		return false;

	main_aux = prog->aux->main_prog_aux ? prog->aux->main_prog_aux : prog->aux;
	real_func_cnt = main_aux->real_func_cnt ?: main_aux->func_cnt;
	if (!main_aux->func || real_func_cnt <= 1)
		return true;

	for (i = 0; i < real_func_cnt; i++) {
		const struct bpf_prog *func = main_aux->func[i];
		u32 subprog_start;
		u32 subprog_end;

		if (!func || !func->aux)
			continue;

		subprog_start = func->aux->subprog_start;
		if (i + 1 < real_func_cnt &&
		    main_aux->func[i + 1] && main_aux->func[i + 1]->aux)
			subprog_end = main_aux->func[i + 1]->aux->subprog_start;
		else
			subprog_end = prog->len;

		if (rule->site_start >= subprog_start && site_end <= subprog_end)
			return true;
		if (rule->site_start < subprog_end)
			return false;
	}

	return false;
}

static struct bpf_jit_policy *bpf_jit_alloc_policy(u32 rule_cnt)
{
	struct bpf_jit_policy *policy;

	policy = kvzalloc(struct_size(policy, rules, rule_cnt),
			  GFP_KERNEL_ACCOUNT);
	if (!policy)
		return ERR_PTR(-ENOMEM);

	policy->rule_cnt = rule_cnt;
	policy->active_cnt = 0;
	policy->blob = NULL;
	return policy;
}

static int bpf_jit_policy_validate_disjoint(const struct bpf_prog *prog,
					    const struct bpf_jit_policy *policy)
{
	const struct bpf_jit_rule *prev, *rule;
	u32 prev_end, rule_end;
	u32 i;

	if (!policy || policy->rule_cnt < 2)
		return 0;

	prev = &policy->rules[0];
	if (check_add_overflow(prev->site_start, prev->site_len, &prev_end))
		return -EINVAL;

	for (i = 1; i < policy->rule_cnt; i++) {
		rule = &policy->rules[i];
		if (check_add_overflow(rule->site_start, rule->site_len,
				       &rule_end))
			return -EINVAL;
		if (rule->site_start < prev_end) {
			bpf_jit_recompile_prog_log(
				prog,
				"policy has overlapping rules: rule %u site %u+%u overlaps rule %u site %u+%u\n",
				prev->user_index, prev->site_start, prev->site_len,
				rule->user_index, rule->site_start, rule->site_len);
			return -EINVAL;
		}

		prev = rule;
		prev_end = rule_end;
	}

	return 0;
}

static struct bpf_jit_policy *
bpf_jit_parse_policy_format_v2(struct bpf_prog *prog,
			       const struct bpf_jit_policy_hdr *hdr,
			       void *blob,
			       size_t blob_len)
{
	const u8 *cursor = (const u8 *)(hdr + 1);
	const u8 *end = (const u8 *)blob + blob_len;
	struct bpf_jit_policy *policy;
	u32 i;

	policy = bpf_jit_alloc_policy(hdr->rule_cnt);
	if (IS_ERR(policy))
		return policy;

	for (i = 0; i < hdr->rule_cnt; i++) {
		const struct bpf_jit_rewrite_rule_v2 *urule;
		struct bpf_jit_rule *rule = &policy->rules[i];
		bool within_subprog;

		if ((size_t)(end - cursor) < sizeof(*urule)) {
			bpf_jit_recompile_prog_log(
				prog,
				"rule %u: truncated rule header (remaining=%zu)\n",
				i, (size_t)(end - cursor));
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		urule = (const struct bpf_jit_rewrite_rule_v2 *)cursor;
		rule->canonical_form = urule->canonical_form;
		rule->native_choice = urule->native_choice;
		memset(&rule->params, 0, sizeof(rule->params));
		rule->site_start = urule->site_start;
		rule->site_len = urule->site_len;
		rule->flags = 0;
		rule->user_index = i;

		if (!bpf_jit_pattern_rule_shape_valid(rule)) {
			bpf_jit_recompile_prog_log(
				prog,
				"rule %u: invalid rule header (form=%u site_len=%u choice=%u)\n",
				i, urule->canonical_form, urule->site_len,
				urule->native_choice);
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		within_subprog = bpf_jit_rule_within_single_subprog(prog, rule);
		if (!within_subprog)
			bpf_jit_recompile_rule_log(
				prog, rule, "crosses subprog boundary");
		if (within_subprog &&
		    bpf_jit_validate_rule(prog, prog->insnsi, prog->len, rule,
					  &rule->params)) {
			rule->flags = BPF_JIT_REWRITE_F_ACTIVE;
			policy->active_cnt++;
		}

		cursor += sizeof(*urule);
	}

	if (cursor != end) {
		bpf_jit_free_policy(policy);
		return ERR_PTR(-EINVAL);
	}

	policy->blob = blob;
	return policy;
}

/**
 * bpf_jit_parse_policy - parse and validate a JIT policy blob from a sealed memfd
 * @prog: the already-verified BPF program
 * @fd:   sealed memfd containing the policy blob
 *
 * Returns a validated bpf_jit_policy, or ERR_PTR on error.
 */
struct bpf_jit_policy *bpf_jit_parse_policy(struct bpf_prog *prog, int fd)
{
	const struct bpf_jit_policy_hdr *hdr;
	struct bpf_jit_policy *policy = NULL;
	struct fd f = fdget(fd);
	size_t blob_len;
	void *blob = NULL;
	loff_t pos = 0;
	ssize_t nread;
	u32 i;

	if (!prog)
		return ERR_PTR(-EINVAL);
	if (fd_empty(f))
		return ERR_PTR(-EBADF);
	if (!bpf_jit_directives_valid_memfd(fd_file(f))) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	blob_len = i_size_read(file_inode(fd_file(f)));
	if (!blob_len || blob_len < sizeof(*hdr)) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}
	if (blob_len > BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE) {
		fdput(f);
		return ERR_PTR(-E2BIG);
	}

	blob = kvzalloc(blob_len, GFP_KERNEL_ACCOUNT);
	if (!blob) {
		fdput(f);
		return ERR_PTR(-ENOMEM);
	}

	nread = kernel_read(fd_file(f), blob, blob_len, &pos);
	fdput(f);
	if (nread < 0) {
		kvfree(blob);
		return ERR_PTR(nread);
	}
	if ((size_t)nread != blob_len) {
		kvfree(blob);
		return ERR_PTR(-EIO);
	}

	hdr = blob;

	/* Validate header */
	if (hdr->magic != BPF_JIT_POLICY_MAGIC ||
	    hdr->hdr_len != sizeof(*hdr)) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy header is invalid (magic=0x%x hdr_len=%u)\n",
			hdr->magic, hdr->hdr_len);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (hdr->total_len != blob_len) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy length mismatch (blob=%zu total_len=%u)\n",
			blob_len, hdr->total_len);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (hdr->rule_cnt > BPF_JIT_MAX_RULES) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy has too many rules (%u > %u)\n",
			hdr->rule_cnt, BPF_JIT_MAX_RULES);
		policy = ERR_PTR(-E2BIG);
		goto out;
	}

	/* Digest binding: insn_cnt must match */
	if (hdr->insn_cnt != prog->len) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy insn_cnt mismatch (blob=%u prog=%u)\n",
			hdr->insn_cnt, prog->len);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	/* Validate prog_tag binding */
	if (memcmp(hdr->prog_tag, prog->tag, sizeof(prog->tag)) != 0) {
		bpf_jit_recompile_prog_log(prog, "policy prog_tag mismatch\n");
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	/* Validate architecture */
#if defined(CONFIG_X86_64)
	if (hdr->arch_id != BPF_JIT_ARCH_X86_64) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy arch mismatch (blob=%u expected=%u)\n",
			hdr->arch_id, BPF_JIT_ARCH_X86_64);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}
#else
	bpf_jit_recompile_prog_log(prog, "policy arch is unsupported\n");
	policy = ERR_PTR(-EOPNOTSUPP);
	goto out;
#endif

	if (!hdr->rule_cnt) {
		bpf_jit_recompile_prog_log(prog, "policy has no rules\n");
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (hdr->version != BPF_JIT_POLICY_VERSION) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy version %u is unsupported\n",
			hdr->version);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}
	if (hdr->flags) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy header has unsupported flags 0x%x\n",
			hdr->flags);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	policy = bpf_jit_parse_policy_format_v2(prog, hdr, blob, blob_len);
	if (!IS_ERR(policy))
		blob = NULL;
	if (IS_ERR(policy))
		goto out;

	/* Sort by site_start for efficient lookup */
	sort(policy->rules, policy->rule_cnt,
	     sizeof(struct bpf_jit_rule), rule_cmp, NULL);
	if (bpf_jit_policy_validate_disjoint(prog, policy)) {
		bpf_jit_free_policy(policy);
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	pr_debug("bpf_jit_recompile: prog insn_cnt=%u rule_cnt=%u active=%u\n",
		 prog->len, policy->rule_cnt, policy->active_cnt);

	for (i = 0; i < policy->rule_cnt; i++) {
		struct bpf_jit_rule *rule = &policy->rules[i];

		pr_debug("bpf_jit_recompile: rule[%u] form=%u site=%u+%u choice=%u -> %s\n",
			 i, rule->canonical_form, rule->site_start,
			 rule->site_len, rule->native_choice,
			 (rule->flags & BPF_JIT_REWRITE_F_ACTIVE) ? "active" : "rejected");
	}

out:
	kvfree(blob);
	return policy;
}

static bool bpf_jit_recompile_has_trampoline_dependency(
	const struct bpf_prog *prog)
{
	if (!prog || !prog->aux)
		return false;

	if (bpf_prog_has_active_trampoline(prog))
		return true;
	if (READ_ONCE(prog->aux->dst_trampoline))
		return true;
	if (bpf_prog_has_trampoline(prog))
		return true;
	if (prog->type == BPF_PROG_TYPE_EXT)
		return true;
	if (prog->type == BPF_PROG_TYPE_STRUCT_OPS &&
	    rcu_access_pointer(prog->aux->st_ops_assoc))
		return true;

	return false;
}

/**
 * bpf_jit_rule_lookup - find the active rule whose site_start matches insn_idx
 *
 * Binary search on the sorted rules array.
 * Returns the first active rule that starts at @insn_idx, or NULL.
 */
const struct bpf_jit_rule *
bpf_jit_rule_lookup(const struct bpf_jit_policy *policy, u32 insn_idx)
{
	u32 lo, hi;

	if (!policy || !policy->active_cnt)
		return NULL;

	lo = 0;
	hi = policy->rule_cnt;
	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;
		const struct bpf_jit_rule *rule = &policy->rules[mid];

		if (insn_idx < rule->site_start) {
			hi = mid;
		} else if (insn_idx > rule->site_start) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}

	for (; lo < policy->rule_cnt; lo++) {
		const struct bpf_jit_rule *rule = &policy->rules[lo];

		if (rule->site_start != insn_idx)
			break;
		if (rule->flags & BPF_JIT_REWRITE_F_ACTIVE)
			return rule;
	}

	return NULL;
}

/**
 * bpf_prog_jit_recompile - BPF_PROG_JIT_RECOMPILE syscall handler
 *
 * Takes a prog_fd for an already-loaded program and a policy_fd
 * for a sealed memfd containing a v5 policy blob.
 * Parses the policy, validates rules, stores the policy on the prog,
 * and triggers a re-JIT.
 */
static int bpf_jit_recompile_prog_images(struct bpf_prog *prog)
{
	struct bpf_prog_aux *main_aux = bpf_prog_main_aux(prog);
	struct bpf_binary_header **old_headers = NULL;
	void __percpu **old_priv_stacks = NULL;
	u64 (*new_exception_cb)(u64 cookie, u64 sp, u64 bp, u64, u64);
	u32 image_cnt = 1;
	u32 real_func_cnt = 0;
	u32 i;
	int err = 0;

	if (main_aux->func_cnt && main_aux->func) {
		real_func_cnt = main_aux->real_func_cnt ?: main_aux->func_cnt;
		image_cnt = real_func_cnt;
	}

	old_headers = kcalloc(image_cnt, sizeof(*old_headers), GFP_KERNEL_ACCOUNT);
	old_priv_stacks = kcalloc(image_cnt, sizeof(*old_priv_stacks),
				  GFP_KERNEL_ACCOUNT);
	if (!old_headers || !old_priv_stacks) {
		err = -ENOMEM;
		goto out_free;
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;

		if (!image_prog) {
			err = -EINVAL;
			goto out_abort;
		}
		bpf_jit_recompile_reset_prog_aux(image_prog);
		image_prog->aux->jit_recompile_active = true;
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;
		bpf_func_t old_bpf_func = READ_ONCE(image_prog->bpf_func);
		struct bpf_prog *recompiled;

		recompiled = bpf_int_jit_compile(image_prog);
		if (recompiled != image_prog ||
		    !bpf_jit_recompile_stage_ok(image_prog, old_bpf_func, false)) {
			err = -EIO;
			goto out_abort;
		}
	}

	if (main_aux->func_cnt && main_aux->func) {
		for (i = 0; i < real_func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];
			struct bpf_insn *insn;
			u32 j;

			if (!func) {
				err = -EINVAL;
				goto out_abort;
			}

			insn = func->insnsi;
			for (j = 0; j < func->len; j++, insn++) {
				int subprog;
				bpf_func_t target;

				if (bpf_pseudo_func(insn)) {
					subprog = insn->off;
					if (subprog < 0 || subprog >= real_func_cnt) {
						err = -EINVAL;
						goto out_abort;
					}
					target = bpf_jit_recompile_staged_func(main_aux->func[subprog]) ?:
						READ_ONCE(main_aux->func[subprog]->bpf_func);
					if (!target) {
						err = -EIO;
						goto out_abort;
					}
					insn[0].imm = (u32)(long)target;
					insn[1].imm = ((u64)(long)target) >> 32;
					continue;
				}
				if (!bpf_pseudo_call_insn(insn))
					continue;

				subprog = insn->off;
				if (subprog < 0 || subprog >= real_func_cnt) {
					err = -EINVAL;
					goto out_abort;
				}
				target = bpf_jit_recompile_staged_func(main_aux->func[subprog]) ?:
					READ_ONCE(main_aux->func[subprog]->bpf_func);
				if (!target) {
					err = -EIO;
					goto out_abort;
				}
				insn->imm = BPF_CALL_IMM(target);
			}
		}

		for (i = 0; i < image_cnt; i++) {
			struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
				main_aux->func[i] : prog;
			bpf_func_t old_bpf_func = READ_ONCE(image_prog->bpf_func);
			struct bpf_prog *recompiled;

			recompiled = bpf_int_jit_compile(image_prog);
			if (recompiled != image_prog ||
			    !bpf_jit_recompile_stage_ok(image_prog, old_bpf_func, true)) {
				err = -EIO;
				goto out_abort;
			}
		}
	}

	/*
	 * When a policy is present but no rule was actually applied, keep the
	 * existing live image. Replacing it with a freshly allocated equivalent
	 * body would perturb relocation-sensitive bytes (for example helper call
	 * displacements) even though the effective lowering did not change.
	 */
	if (main_aux->jit_policy && !main_aux->jit_recompile_num_applied)
		goto out_no_commit;

	new_exception_cb = main_aux->bpf_exception_cb;
	if (main_aux->func_cnt && main_aux->func) {
		for (i = 0; i < real_func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];

			if (func && func->aux->exception_cb) {
				new_exception_cb = (void *)(bpf_jit_recompile_staged_func(func) ?:
						READ_ONCE(func->bpf_func));
				break;
			}
		}
	} else if (prog->aux->exception_cb) {
		new_exception_cb = (void *)(bpf_jit_recompile_staged_func(prog) ?:
				 READ_ONCE(prog->bpf_func));
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;
		struct bpf_prog *ksym_prog;

		if (!(main_aux->func_cnt && main_aux->func) || !i)
			ksym_prog = prog;
		else if (i < real_func_cnt)
			ksym_prog = main_aux->func[i];
		else
			ksym_prog = NULL;

		if (image_prog->jited && image_prog->bpf_func)
			old_headers[i] = bpf_jit_binary_pack_hdr(image_prog);
		if (image_prog->aux->priv_stack_ptr !=
		    image_prog->aux->jit_recompile_priv_stack_ptr)
			old_priv_stacks[i] = image_prog->aux->priv_stack_ptr;

		if (!ksym_prog)
			continue;

		bpf_jit_recompile_shadow_ksym_add(
			ksym_prog, bpf_jit_recompile_staged_func(image_prog) ?:
				READ_ONCE(image_prog->bpf_func),
			bpf_jit_recompile_staged_len(image_prog),
			bpf_jit_recompile_staged_extable(image_prog),
			bpf_jit_recompile_staged_num_exentries(image_prog),
			bpf_jit_recompile_staged_fp_start(image_prog),
			bpf_jit_recompile_staged_fp_end(image_prog));
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;

		err = bpf_jit_recompile_commit(image_prog);
		if (err)
			goto out_abort;
	}

	if (main_aux->func_cnt && main_aux->func) {
		prog->jited = 1;
		prog->jited_len = main_aux->func[0]->jited_len;
		prog->aux->extable = main_aux->func[0]->aux->extable;
		prog->aux->num_exentries = main_aux->func[0]->aux->num_exentries;
		prog->aux->exception_boundary =
			main_aux->func[0]->aux->exception_boundary;
		prog->aux->ksym.fp_start = main_aux->func[0]->aux->ksym.fp_start;
		prog->aux->ksym.fp_end = main_aux->func[0]->aux->ksym.fp_end;
		smp_store_release(&prog->bpf_func, main_aux->func[0]->bpf_func);
	}
	if (new_exception_cb)
		smp_store_release(&main_aux->bpf_exception_cb, new_exception_cb);

	synchronize_rcu();

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;
		struct bpf_prog *ksym_prog;

		if (!(main_aux->func_cnt && main_aux->func) || !i)
			ksym_prog = prog;
		else if (i < real_func_cnt)
			ksym_prog = main_aux->func[i];
		else
			ksym_prog = NULL;

		if (ksym_prog)
			bpf_prog_kallsyms_replace(
				ksym_prog, &ksym_prog->aux->jit_recompile_ksym,
				(unsigned long)READ_ONCE(ksym_prog->bpf_func),
				ksym_prog->jited_len, ksym_prog->aux->extable,
				ksym_prog->aux->num_exentries,
				ksym_prog->aux->ksym.fp_start,
				ksym_prog->aux->ksym.fp_end);

		if (old_headers[i] &&
		    old_headers[i] != bpf_jit_binary_pack_hdr(image_prog))
			bpf_jit_binary_pack_free(old_headers[i], NULL);
		if (old_priv_stacks[i])
			free_percpu(old_priv_stacks[i]);

		image_prog->aux->jit_recompile_active = false;
	}
	goto out_free;

out_no_commit:
	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;

		if (!image_prog)
			continue;
		bpf_jit_recompile_abort(image_prog);
		image_prog->aux->jit_recompile_active = false;
	}

out_free:
	kfree(old_priv_stacks);
	kfree(old_headers);
	return err;

out_abort:
	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog = main_aux->func_cnt && main_aux->func ?
			main_aux->func[i] : prog;
		struct bpf_prog *ksym_prog;

		if (!(main_aux->func_cnt && main_aux->func) || !i)
			ksym_prog = prog;
		else if (i < real_func_cnt)
			ksym_prog = main_aux->func[i];
		else
			ksym_prog = NULL;

		if (ksym_prog)
			bpf_jit_recompile_shadow_ksym_del(ksym_prog);
		if (image_prog) {
			bpf_jit_recompile_abort(image_prog);
			image_prog->aux->jit_recompile_active = false;
		}
	}
	goto out_free;
}

int bpf_prog_jit_recompile(union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct bpf_prog_aux *main_aux = NULL;
	struct bpf_jit_policy *policy = NULL;
	struct bpf_jit_policy *old_policy = NULL;
	struct bpf_verifier_log log = {};
	struct bpf_jit_recompile_rollback_state rollback = {};
	bool locked = false;
	bool stock_rejit;
	u32 log_level = 0;
	u32 log_size_actual = 0;
	int log_err = 0;
	int err = 0;

	if (attr->jit_recompile.flags)
		return -EINVAL;

	if (!bpf_jit_supports_recompile())
		return -EOPNOTSUPP;

	stock_rejit = attr->jit_recompile.policy_fd == 0;

	if (!capable(CAP_BPF) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	prog = bpf_prog_get(attr->jit_recompile.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	main_aux = bpf_prog_main_aux(prog);
	if (!mutex_trylock(&main_aux->jit_recompile_mutex)) {
		err = -EBUSY;
		goto out_put;
	}
	locked = true;

	if (attr->jit_recompile.log_level &&
	    attr->jit_recompile.log_buf &&
	    attr->jit_recompile.log_size) {
		log_level = BPF_LOG_LEVEL1 | BPF_LOG_FIXED;
	}

	err = bpf_vlog_init(&log, log_level,
			    log_level ?
			    u64_to_user_ptr(attr->jit_recompile.log_buf) : NULL,
			    log_level ?
			    min_t(u32, attr->jit_recompile.log_size,
				  BPF_JIT_RECOMPILE_LOG_MAX_SIZE) : 0);
	if (err)
		goto out_put;
	main_aux->jit_recompile_log = &log;

	/* Must be a JITed program */
	if (!prog->jited) {
		bpf_jit_recompile_prog_log(prog, "program is not JITed\n");
		err = -EINVAL;
		goto out_put;
	}

	if (bpf_jit_recompile_has_trampoline_dependency(prog)) {
		bpf_jit_recompile_prog_log(
			prog,
			"trampoline-linked programs are not supported: active trampoline users or trampoline-attached execution require trampoline regeneration\n");
		err = -EOPNOTSUPP;
		goto out_put;
	}

	/* Don't support blinded programs in POC */
	if (prog->blinded) {
		bpf_jit_recompile_prog_log(prog,
					   "blinded programs are not supported\n");
		err = -EOPNOTSUPP;
		goto out_put;
	}

	if (!stock_rejit) {
		/* Parse and validate policy blob */
		policy = bpf_jit_parse_policy(prog, attr->jit_recompile.policy_fd);
		if (IS_ERR(policy)) {
			err = PTR_ERR(policy);
			policy = NULL;
			goto out_put;
		}

		if (policy->active_cnt == 0) {
			bpf_jit_recompile_prog_log(prog,
						   "policy has no active rules\n");
			bpf_jit_free_policy(policy);
			policy = NULL;
			err = -EINVAL;
			goto out_put;
		}
	}

	err = bpf_jit_recompile_snapshot(prog, &rollback);
	if (err) {
		bpf_jit_recompile_prog_log(prog,
					   "failed to save rollback state: err=%d\n",
					   err);
		goto out_put;
	}

	/* Stock re-JIT (clear policy) */
	if (stock_rejit) {
		old_policy = main_aux->jit_policy;
		main_aux->jit_policy = NULL;
		goto do_recompile;
	}

	/* Swap policy on prog */
	old_policy = main_aux->jit_policy;
	main_aux->jit_policy = policy;
	policy = NULL;

do_recompile:
	main_aux->jit_recompile_num_applied = 0;

	/* Trigger re-JIT for the active func[] images. */
	err = bpf_jit_recompile_prog_images(prog);
	if (err) {
		struct bpf_jit_policy *failed_policy = NULL;

		bpf_jit_recompile_prog_log(prog,
					   "re-JIT failed with err=%d\n", err);
		bpf_jit_recompile_restore(&rollback);
		failed_policy = main_aux->jit_policy;
		main_aux->jit_policy = old_policy;
		old_policy = NULL;
		if (failed_policy != main_aux->jit_policy)
			bpf_jit_free_policy(failed_policy);
		bpf_jit_recompile_prog_log(
			prog,
			"restored the pre-recompile image and policy\n");
		goto out_put;
	}

	if (old_policy) {
		bpf_jit_free_policy(old_policy);
		old_policy = NULL;
	}
	if (!stock_rejit && !main_aux->jit_recompile_num_applied) {
		bpf_jit_recompile_restore(&rollback);
		bpf_jit_recompile_prog_log(
			prog,
			"no rules applied; kept the pre-recompile image\n");
	}

out_put:
	main_aux->jit_recompile_num_applied = 0;
	if (main_aux)
		main_aux->jit_recompile_log = NULL;
	if (locked)
		mutex_unlock(&main_aux->jit_recompile_mutex);
	log_err = bpf_vlog_finalize(&log, &log_size_actual);
	if (log_err == -ENOSPC)
		log_err = 0;
	if (!err && log_err)
		err = log_err;
	bpf_jit_recompile_snapshot_free(&rollback);
	bpf_jit_free_policy(policy);
	bpf_jit_free_policy(old_policy);
	bpf_prog_put(prog);
	return err;
}
