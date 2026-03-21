// SPDX-License-Identifier: GPL-2.0-only
/* BPF JIT canonical site validators */
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/overflow.h>
#include <linux/slab.h>

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

static bool bpf_jit_is_cmov_cond_jump(const struct bpf_insn *insn)
{
	u8 cls = BPF_CLASS(insn->code);

	if (cls != BPF_JMP && cls != BPF_JMP32)
		return false;
	if (BPF_SRC(insn->code) != BPF_X && BPF_SRC(insn->code) != BPF_K)
		return false;

	return bpf_jit_cond_op_valid(BPF_OP(insn->code));
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

enum bpf_jit_pattern_field {
	BPF_JIT_PATTERN_FIELD_CODE = 0,
	BPF_JIT_PATTERN_FIELD_CODE_CLASS,
	BPF_JIT_PATTERN_FIELD_CODE_SRC,
	BPF_JIT_PATTERN_FIELD_DST_REG,
	BPF_JIT_PATTERN_FIELD_SRC_REG,
	BPF_JIT_PATTERN_FIELD_OFF,
	BPF_JIT_PATTERN_FIELD_IMM,
};

enum bpf_jit_pattern_check_op {
	BPF_JIT_PATTERN_CHECK_EQ_CONST = 0,
	BPF_JIT_PATTERN_CHECK_RANGE,
	BPF_JIT_PATTERN_CHECK_CAPTURE,
	BPF_JIT_PATTERN_CHECK_EQ_CAPTURE,
	BPF_JIT_PATTERN_CHECK_NE_CAPTURE,
};

enum bpf_jit_pattern_extract_kind {
	BPF_JIT_PATTERN_EXTRACT_REG_FIELD = 0,
	BPF_JIT_PATTERN_EXTRACT_IMM_FIELD,
	BPF_JIT_PATTERN_EXTRACT_CONST_IMM,
};

#define BPF_JIT_PATTERN_MAX_CAPTURES	8

struct bpf_jit_pattern_check {
	u8 insn_idx;
	u8 field;
	u8 op;
	u8 slot;
	s64 value;
	s64 value2;
};

struct bpf_jit_pattern_extract {
	u8 param;
	u8 kind;
	u8 insn_idx;
	u8 field;
	s64 value;
};

struct bpf_jit_pattern_bound {
	u8 param;
	s64 min;
	s64 max;
};

struct bpf_jit_form_pattern;

typedef bool (*bpf_jit_pattern_post_fn)(
	const struct bpf_insn *site,
	const struct bpf_jit_rule *rule,
	const struct bpf_jit_form_pattern *pattern,
	struct bpf_jit_canonical_params *params);

struct bpf_jit_form_pattern {
	u8 site_len;
	const struct bpf_jit_pattern_check *checks;
	u8 nr_checks;
	const struct bpf_jit_pattern_extract *extracts;
	u8 nr_extracts;
	const struct bpf_jit_pattern_bound *bounds;
	u8 nr_bounds;
	bpf_jit_pattern_post_fn post;
	s64 post_arg;
};

struct bpf_jit_pattern_state {
	s64 captures[BPF_JIT_PATTERN_MAX_CAPTURES];
	unsigned long capture_mask;
};

static bool bpf_jit_pattern_field_value(const struct bpf_insn *insn, u8 field,
					s64 *value)
{
	switch (field) {
	case BPF_JIT_PATTERN_FIELD_CODE:
		*value = insn->code;
		return true;
	case BPF_JIT_PATTERN_FIELD_CODE_CLASS:
		*value = BPF_CLASS(insn->code);
		return true;
	case BPF_JIT_PATTERN_FIELD_CODE_SRC:
		*value = BPF_SRC(insn->code);
		return true;
	case BPF_JIT_PATTERN_FIELD_DST_REG:
		*value = insn->dst_reg;
		return true;
	case BPF_JIT_PATTERN_FIELD_SRC_REG:
		*value = insn->src_reg;
		return true;
	case BPF_JIT_PATTERN_FIELD_OFF:
		*value = insn->off;
		return true;
	case BPF_JIT_PATTERN_FIELD_IMM:
		*value = insn->imm;
		return true;
	default:
		return false;
	}
}

static bool
bpf_jit_pattern_check_match(const struct bpf_insn *site,
			    const struct bpf_jit_pattern_check *check,
			    struct bpf_jit_pattern_state *state)
{
	s64 value;

	if (check->slot >= BPF_JIT_PATTERN_MAX_CAPTURES)
		return false;
	if (!bpf_jit_pattern_field_value(&site[check->insn_idx], check->field, &value))
		return false;

	switch (check->op) {
	case BPF_JIT_PATTERN_CHECK_EQ_CONST:
		return value == check->value;
	case BPF_JIT_PATTERN_CHECK_RANGE:
		return value >= check->value && value <= check->value2;
	case BPF_JIT_PATTERN_CHECK_CAPTURE:
		state->captures[check->slot] = value;
		state->capture_mask |= BIT(check->slot);
		return true;
	case BPF_JIT_PATTERN_CHECK_EQ_CAPTURE:
		if (!(state->capture_mask & BIT(check->slot)))
			return false;
		return value == state->captures[check->slot];
	case BPF_JIT_PATTERN_CHECK_NE_CAPTURE:
		if (!(state->capture_mask & BIT(check->slot)))
			return false;
		return value != state->captures[check->slot];
	default:
		return false;
	}
}

static bool
bpf_jit_pattern_extract_params(const struct bpf_insn *site,
			       const struct bpf_jit_pattern_extract *extracts,
			       u32 nr_extracts,
			       struct bpf_jit_canonical_params *params)
{
	u32 i;

	for (i = 0; i < nr_extracts; i++) {
		const struct bpf_jit_pattern_extract *extract = &extracts[i];
		s64 value;

		switch (extract->kind) {
		case BPF_JIT_PATTERN_EXTRACT_REG_FIELD:
			if (!bpf_jit_pattern_field_value(&site[extract->insn_idx],
							 extract->field, &value))
				return false;
			bpf_jit_param_set_reg(params, extract->param, (u8)value);
			break;
		case BPF_JIT_PATTERN_EXTRACT_IMM_FIELD:
			if (!bpf_jit_pattern_field_value(&site[extract->insn_idx],
							 extract->field, &value))
				return false;
			bpf_jit_param_set_imm(params, extract->param, value);
			break;
		case BPF_JIT_PATTERN_EXTRACT_CONST_IMM:
			bpf_jit_param_set_imm(params, extract->param, extract->value);
			break;
		default:
			return false;
		}
	}

	return true;
}

static bool
bpf_jit_pattern_bounds_ok(const struct bpf_jit_canonical_params *params,
			  const struct bpf_jit_pattern_bound *bounds,
			  u32 nr_bounds)
{
	u32 i;

	for (i = 0; i < nr_bounds; i++) {
		s64 value = bpf_jit_param_imm(params, bounds[i].param);

		if (value < bounds[i].min || value > bounds[i].max)
			return false;
	}

	return true;
}

static bool
bpf_jit_match_form_pattern(const struct bpf_insn *site,
			   const struct bpf_jit_rule *rule,
			   const struct bpf_jit_form_pattern *pattern,
			   struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_pattern_state state = {};
	u32 i;

	if (rule->site_len != pattern->site_len)
		return false;

	for (i = 0; i < pattern->nr_checks; i++) {
		if (!bpf_jit_pattern_check_match(site, &pattern->checks[i], &state))
			return false;
	}

	memset(params, 0, sizeof(*params));
	if (!bpf_jit_pattern_extract_params(site, pattern->extracts,
					    pattern->nr_extracts, params))
		return false;
	if (pattern->post && !pattern->post(site, rule, pattern, params))
		return false;
	if (!bpf_jit_pattern_bounds_ok(params, pattern->bounds, pattern->nr_bounds))
		return false;

	return true;
}

static bool
bpf_jit_validate_form_patterns(const struct bpf_insn *insns, u32 insn_cnt,
			       const struct bpf_jit_rule *rule,
			       const struct bpf_jit_form_pattern *patterns,
			       u32 nr_patterns,
			       struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_canonical_params candidate;
	u32 i;

	if (!bpf_jit_site_range_valid(rule->site_start, rule->site_len, insn_cnt, NULL))
		return false;

	for (i = 0; i < nr_patterns; i++) {
		if (!bpf_jit_match_form_pattern(&insns[rule->site_start], rule,
						&patterns[i], &candidate))
			continue;
		if (params)
			*params = candidate;
		return true;
	}

	return false;
}

#define BPF_JIT_PATTERN_EQ(_insn, _field, _value)				\
	{								\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
		.op = BPF_JIT_PATTERN_CHECK_EQ_CONST,			\
		.value = (_value),					\
	}

#define BPF_JIT_PATTERN_RANGE(_insn, _field, _min, _max)			\
	{								\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
		.op = BPF_JIT_PATTERN_CHECK_RANGE,			\
		.value = (_min),					\
		.value2 = (_max),					\
	}

#define BPF_JIT_PATTERN_CAPTURE(_insn, _field, _slot)			\
	{								\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
		.op = BPF_JIT_PATTERN_CHECK_CAPTURE,			\
		.slot = (_slot),					\
	}

#define BPF_JIT_PATTERN_EQ_CAPTURE(_insn, _field, _slot)			\
	{								\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
		.op = BPF_JIT_PATTERN_CHECK_EQ_CAPTURE,		\
		.slot = (_slot),					\
	}

#define BPF_JIT_PATTERN_NE_CAPTURE(_insn, _field, _slot)			\
	{								\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
		.op = BPF_JIT_PATTERN_CHECK_NE_CAPTURE,		\
		.slot = (_slot),					\
	}

#define BPF_JIT_PATTERN_EXTRACT_REG(_param, _insn, _field)		\
	{								\
		.param = (_param),					\
		.kind = BPF_JIT_PATTERN_EXTRACT_REG_FIELD,		\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
	}

#define BPF_JIT_PATTERN_EXTRACT_IMM(_param, _insn, _field)		\
	{								\
		.param = (_param),					\
		.kind = BPF_JIT_PATTERN_EXTRACT_IMM_FIELD,		\
		.insn_idx = (_insn),					\
		.field = BPF_JIT_PATTERN_FIELD_##_field,		\
	}

#define BPF_JIT_PATTERN_CONST_IMM(_param, _value)			\
	{								\
		.param = (_param),					\
		.kind = BPF_JIT_PATTERN_EXTRACT_CONST_IMM,		\
		.value = (_value),					\
	}

#define BPF_JIT_PATTERN_BOUND(_param, _min, _max)			\
	{								\
		.param = (_param),					\
		.min = (_min),						\
		.max = (_max),						\
	}

#define BPF_JIT_FORM_PATTERN_INIT(_site_len, _checks, _extracts, _post,	\
				  _post_arg)				\
	{								\
		.site_len = (_site_len),				\
		.checks = (_checks),					\
		.nr_checks = ARRAY_SIZE(_checks),			\
		.extracts = (_extracts),				\
		.nr_extracts = ARRAY_SIZE(_extracts),			\
		.post = (_post),					\
		.post_arg = (_post_arg),				\
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

static bool bpf_jit_cond_select_has_dst_alias(
	const struct bpf_jit_cond_select_shape *shape)
{
	if (shape->dst_reg == shape->cond_a)
		return true;

	return shape->cond_b.type == BPF_JIT_BIND_VAL_REG &&
	       shape->dst_reg == shape->cond_b.value;
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
	if (bpf_jit_cond_select_has_dst_alias(&shape))
		return false;

	if (params)
		bpf_jit_cond_select_fill_params(params, &shape);

	return true;
}

#define BPF_JIT_WMEM_HEAD_COMMON \
	BPF_JIT_PATTERN_EQ(0, CODE, BPF_LDX | BPF_MEM | BPF_B), BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0), BPF_JIT_PATTERN_CAPTURE(0, SRC_REG, 1)
#define BPF_JIT_WMEM_BODY_COMMON \
	BPF_JIT_PATTERN_EQ(0, CODE, BPF_LDX | BPF_MEM | BPF_B), BPF_JIT_PATTERN_EQ_CAPTURE(0, SRC_REG, 1), BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 2), BPF_JIT_PATTERN_NE_CAPTURE(0, DST_REG, 0)
#define BPF_JIT_WMEM_SHIFT_CHECKS(_insn, _slot) \
	BPF_JIT_PATTERN_EQ((_insn), CODE, BPF_ALU64 | BPF_LSH | BPF_K), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), DST_REG, (_slot)), BPF_JIT_PATTERN_EQ((_insn), OFF, 0), BPF_JIT_PATTERN_RANGE((_insn), IMM, 1, 63)
#define BPF_JIT_WMEM_OR_CHECKS(_insn) \
	BPF_JIT_PATTERN_EQ((_insn), CODE, BPF_ALU64 | BPF_OR | BPF_X), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), DST_REG, 0), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), SRC_REG, 2), BPF_JIT_PATTERN_EQ((_insn), OFF, 0), BPF_JIT_PATTERN_EQ((_insn), IMM, 0)
#define BPF_JIT_WMEM_HEAD_PATTERN_DECL(_name, _tail) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_WMEM_HEAD_COMMON, _tail };
#define BPF_JIT_WMEM_BODY_OR_PATTERN_DECL(_name) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_WMEM_BODY_COMMON, BPF_JIT_WMEM_OR_CHECKS(1), };
#define BPF_JIT_WMEM_BODY_SHIFT_PATTERN_DECL(_name) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_WMEM_BODY_COMMON, BPF_JIT_WMEM_SHIFT_CHECKS(1, 2), BPF_JIT_WMEM_OR_CHECKS(2), };
#define BPF_JIT_WMEM_CHUNK_PATTERN(_len, _name, _shifted) \
	{ .site_len = (_len), .checks = _name##_checks, .nr_checks = ARRAY_SIZE(_name##_checks), .post_arg = (_shifted), }

BPF_JIT_WMEM_HEAD_PATTERN_DECL(bpf_jit_wide_mem_head_shift, BPF_JIT_WMEM_SHIFT_CHECKS(1, 0));
BPF_JIT_WMEM_HEAD_PATTERN_DECL(bpf_jit_wide_mem_head_load, );
BPF_JIT_WMEM_BODY_SHIFT_PATTERN_DECL(bpf_jit_wide_mem_body_shift);
BPF_JIT_WMEM_BODY_OR_PATTERN_DECL(bpf_jit_wide_mem_body_or);

static const struct bpf_jit_form_pattern bpf_jit_wide_mem_head_patterns[] = {
	BPF_JIT_WMEM_CHUNK_PATTERN(2, bpf_jit_wide_mem_head_shift, 1),
	BPF_JIT_WMEM_CHUNK_PATTERN(1, bpf_jit_wide_mem_head_load, 0),
};

static const struct bpf_jit_form_pattern bpf_jit_wide_mem_body_patterns[] = {
	BPF_JIT_WMEM_CHUNK_PATTERN(3, bpf_jit_wide_mem_body_shift, 1),
	BPF_JIT_WMEM_CHUNK_PATTERN(2, bpf_jit_wide_mem_body_or, 0),
};

static const struct bpf_jit_form_pattern *
bpf_jit_wide_mem_match_any(const struct bpf_insn *site, u32 site_len,
			   const struct bpf_jit_form_pattern *patterns, u32 nr_patterns,
			   struct bpf_jit_pattern_state *state)
{
	u32 i, j;

	for (i = 0; i < nr_patterns; i++) {
		struct bpf_jit_pattern_state candidate = *state;

		if (site_len < patterns[i].site_len)
			continue;
		for (j = 0; j < patterns[i].nr_checks; j++)
			if (patterns[i].checks[j].insn_idx >= patterns[i].site_len ||
			    !bpf_jit_pattern_check_match(site, &patterns[i].checks[j], &candidate))
				goto next_pattern;
		*state = candidate;
		return &patterns[i];
next_pattern:
		;
	}

	return NULL;
}

static void
bpf_jit_wide_mem_record_chunk(const struct bpf_insn *site,
			      const struct bpf_jit_form_pattern *pattern,
			      s16 *offsets, u8 *shifts, u32 idx)
{
	offsets[idx] = site[0].off;
	shifts[idx] = pattern->post_arg ? (u8)site[1].imm : 0;
}

static bool
bpf_jit_normalize_wide_mem_shape(const struct bpf_insn *first,
				 const s16 *offsets, const u8 *shifts,
				 u32 count,
				 struct bpf_jit_wide_mem_shape *shape)
{
	s16 min_off, max_off;
	u32 i, j;
	bool little_endian = true;
	bool big_endian = true;

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
 * Supports two linearized patterns with variable width:
 *   1. Low-byte-first: ldxb dst, [base+off]; ldxb tmp, [base+off+1]; lsh tmp, 8; or dst, tmp; ...
 *   2. High-byte-first (clang): ldxb tmp, [base+off+1]; lsh tmp, 8; ldxb dst, [base+off]; or tmp, dst
 */
static bool
bpf_jit_validate_wide_mem_rule(const struct bpf_insn *insns,
			       u32 insn_cnt,
			       const struct bpf_jit_rule *rule,
			       struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_pattern_state state = {};
	struct bpf_jit_wide_mem_shape shape;
	const struct bpf_jit_form_pattern *pattern;
	const struct bpf_insn *site;
	s16 offsets[8];
	u8 shifts[8];
	u32 pos = 0, count = 0;
	s64 encoded_width;

	if (!bpf_jit_site_range_valid(rule->site_start, rule->site_len,
				      insn_cnt, NULL) ||
	    rule->site_len < 4)
		return false;

	site = &insns[rule->site_start];
	pattern = bpf_jit_wide_mem_match_any(site, rule->site_len,
					     bpf_jit_wide_mem_head_patterns,
					     ARRAY_SIZE(bpf_jit_wide_mem_head_patterns),
					     &state);
	if (!pattern)
		return false;

	bpf_jit_wide_mem_record_chunk(site, pattern, offsets, shifts, count++);
	pos += pattern->site_len;

	while (pos < rule->site_len) {
		if (count == ARRAY_SIZE(offsets))
			return false;

		pattern = bpf_jit_wide_mem_match_any(&site[pos],
						     rule->site_len - pos,
						     bpf_jit_wide_mem_body_patterns,
						     ARRAY_SIZE(bpf_jit_wide_mem_body_patterns),
						     &state);
		if (!pattern)
			return false;

		bpf_jit_wide_mem_record_chunk(&site[pos], pattern,
					       offsets, shifts, count++);
		pos += pattern->site_len;
	}

	if (count < 2 || count > 8)
		return false;
	if (rule->site_len != 3 * count - 2)
		return false;
	if (!bpf_jit_normalize_wide_mem_shape(site, offsets, shifts, count, &shape))
		return false;

	encoded_width = shape.width |
			(shape.big_endian ? BPF_JIT_WMEM_F_BIG_ENDIAN : 0);
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

/* Masked rotate accepts only the canonical high-mask for the left shift. */
static bool bpf_jit_rotate_mask_matches(u32 rot_amount, s32 imm)
{
	u32 high_mask;
	u32 mask = (u32)imm;

	if (!rot_amount || rot_amount >= 32)
		return false;

	high_mask = ~((1U << (32 - rot_amount)) - 1);

	return mask == high_mask;
}

#define BPF_JIT_ROT_POST_ALLOW_SWAP	(1ULL << 0)
#define BPF_JIT_ROT_POST_SHIFT1_SHIFT	8
#define BPF_JIT_ROT_POST_SHIFT2_SHIFT	16
#define BPF_JIT_ROT_POST_MASK_SHIFT	24
#define BPF_JIT_ROT_POST_NO_MASK	0xff

#define BPF_JIT_ROT_POST_ARG(_shift1, _shift2, _mask, _swap) \
	((s64)(((_swap) ? BPF_JIT_ROT_POST_ALLOW_SWAP : 0) | ((u64)(_shift1) << BPF_JIT_ROT_POST_SHIFT1_SHIFT) | ((u64)(_shift2) << BPF_JIT_ROT_POST_SHIFT2_SHIFT) | ((u64)(_mask) << BPF_JIT_ROT_POST_MASK_SHIFT)))
#define BPF_JIT_ROT_FIRST_COPY_CHECKS(_code) \
	BPF_JIT_PATTERN_EQ(0, CODE, (_code)), BPF_JIT_PATTERN_EQ(0, OFF, 0), BPF_JIT_PATTERN_EQ(0, IMM, 0), BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0), BPF_JIT_PATTERN_CAPTURE(0, SRC_REG, 1), BPF_JIT_PATTERN_NE_CAPTURE(0, DST_REG, 1)
#define BPF_JIT_ROT_SHIFT_CHECKS(_insn, _class, _dst_slot, _width) \
	BPF_JIT_PATTERN_EQ((_insn), CODE_CLASS, (_class)), BPF_JIT_PATTERN_EQ((_insn), CODE_SRC, BPF_K), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), DST_REG, (_dst_slot)), BPF_JIT_PATTERN_EQ((_insn), OFF, 0), BPF_JIT_PATTERN_RANGE((_insn), IMM, 1, (_width) - 1)
#define BPF_JIT_ROT_SECOND_COPY_CHECKS(_insn, _dst_slot) \
	BPF_JIT_PATTERN_EQ((_insn), CODE, BPF_ALU64 | BPF_MOV | BPF_X), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), SRC_REG, 1), BPF_JIT_PATTERN_EQ((_insn), OFF, 0), BPF_JIT_PATTERN_EQ((_insn), IMM, 0), BPF_JIT_PATTERN_CAPTURE((_insn), DST_REG, (_dst_slot)), BPF_JIT_PATTERN_NE_CAPTURE((_insn), DST_REG, 0)
#define BPF_JIT_ROT_OR_CHECKS(_insn, _code, _dst_slot) \
	BPF_JIT_PATTERN_EQ((_insn), CODE, (_code)), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), DST_REG, (_dst_slot)), BPF_JIT_PATTERN_EQ_CAPTURE((_insn), SRC_REG, 0), BPF_JIT_PATTERN_EQ((_insn), OFF, 0), BPF_JIT_PATTERN_EQ((_insn), IMM, 0)

static bool
bpf_jit_finalize_rotate(const struct bpf_insn *site,
			const struct bpf_jit_rule *rule,
			const struct bpf_jit_form_pattern *pattern,
			struct bpf_jit_canonical_params *params)
{
	u32 width = (u32)bpf_jit_param_imm(params, BPF_JIT_ROT_PARAM_WIDTH),
	    shift1_idx = ((u64)pattern->post_arg >> BPF_JIT_ROT_POST_SHIFT1_SHIFT) & 0xff,
	    shift2_idx = ((u64)pattern->post_arg >> BPF_JIT_ROT_POST_SHIFT2_SHIFT) & 0xff,
	    mask_idx = ((u64)pattern->post_arg >> BPF_JIT_ROT_POST_MASK_SHIFT) & 0xff,
	    rot_amount, rsh_amount;

	(void)rule;

	if (pattern->post_arg & BPF_JIT_ROT_POST_ALLOW_SWAP) {
		if (BPF_OP(site[shift1_idx].code) == BPF_LSH &&
		    BPF_OP(site[shift2_idx].code) == BPF_RSH) {
			rot_amount = (u32)site[shift1_idx].imm;
			rsh_amount = (u32)site[shift2_idx].imm;
		} else if (BPF_OP(site[shift1_idx].code) == BPF_RSH &&
			   BPF_OP(site[shift2_idx].code) == BPF_LSH) {
			rsh_amount = (u32)site[shift1_idx].imm;
			rot_amount = (u32)site[shift2_idx].imm;
		} else {
			return false;
		}
	} else {
		if (BPF_OP(site[shift1_idx].code) != BPF_RSH ||
		    BPF_OP(site[shift2_idx].code) != BPF_LSH)
			return false;

		rsh_amount = (u32)site[shift1_idx].imm;
		rot_amount = (u32)site[shift2_idx].imm;
	}

	if (rot_amount + rsh_amount != width)
		return false;
	if (mask_idx != BPF_JIT_ROT_POST_NO_MASK &&
	    !bpf_jit_rotate_mask_matches(rot_amount, site[mask_idx].imm))
		return false;

	bpf_jit_param_set_imm(params, BPF_JIT_ROT_PARAM_AMOUNT, rot_amount);
	return true;
}

#define BPF_JIT_ROT_INPLACE_PATTERN_DECL(_name, _class, _width) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_ROT_FIRST_COPY_CHECKS((_class) | BPF_MOV | BPF_X), BPF_JIT_ROT_SHIFT_CHECKS(1, (_class), 0, (_width)), BPF_JIT_ROT_SHIFT_CHECKS(2, (_class), 1, (_width)), BPF_JIT_ROT_OR_CHECKS(3, (_class) | BPF_OR | BPF_X, 1), }; \
static const struct bpf_jit_pattern_extract _name##_extracts[] = { BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_DST_REG, 0, SRC_REG), BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_SRC_REG, 0, SRC_REG), BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ROT_PARAM_WIDTH, (_width)), };
#define BPF_JIT_ROT_TWOCOPY_PATTERN_DECL(_name, _width) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_ROT_FIRST_COPY_CHECKS(BPF_ALU64 | BPF_MOV | BPF_X), BPF_JIT_ROT_SHIFT_CHECKS(1, BPF_ALU64, 0, (_width)), BPF_JIT_ROT_SECOND_COPY_CHECKS(2, 2), BPF_JIT_ROT_SHIFT_CHECKS(3, BPF_ALU64, 2, (_width)), BPF_JIT_ROT_OR_CHECKS(4, BPF_ALU64 | BPF_OR | BPF_X, 2), }; \
static const struct bpf_jit_pattern_extract _name##_extracts[] = { BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_DST_REG, 2, DST_REG), BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_SRC_REG, 0, SRC_REG), BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ROT_PARAM_WIDTH, (_width)), };
#define BPF_JIT_ROT_MASKED_INPLACE_PATTERN_DECL(_name) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_ROT_FIRST_COPY_CHECKS(BPF_ALU64 | BPF_MOV | BPF_X), BPF_JIT_PATTERN_EQ(1, CODE, BPF_ALU64 | BPF_AND | BPF_K), BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0), BPF_JIT_PATTERN_EQ(1, OFF, 0), BPF_JIT_ROT_SHIFT_CHECKS(2, BPF_ALU64, 0, 32), BPF_JIT_ROT_SHIFT_CHECKS(3, BPF_ALU64, 1, 32), BPF_JIT_ROT_OR_CHECKS(4, BPF_ALU64 | BPF_OR | BPF_X, 1), }; \
static const struct bpf_jit_pattern_extract _name##_extracts[] = { BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_DST_REG, 0, SRC_REG), BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_SRC_REG, 0, SRC_REG), BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ROT_PARAM_WIDTH, 32), };
#define BPF_JIT_ROT_MASKED_TWOCOPY_PATTERN_DECL(_name) \
static const struct bpf_jit_pattern_check _name##_checks[] = { BPF_JIT_ROT_FIRST_COPY_CHECKS(BPF_ALU64 | BPF_MOV | BPF_X), BPF_JIT_PATTERN_EQ(1, CODE, BPF_ALU64 | BPF_AND | BPF_K), BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0), BPF_JIT_PATTERN_EQ(1, OFF, 0), BPF_JIT_ROT_SHIFT_CHECKS(2, BPF_ALU64, 0, 32), BPF_JIT_ROT_SECOND_COPY_CHECKS(3, 2), BPF_JIT_ROT_SHIFT_CHECKS(4, BPF_ALU64, 2, 32), BPF_JIT_ROT_OR_CHECKS(5, BPF_ALU64 | BPF_OR | BPF_X, 2), }; \
static const struct bpf_jit_pattern_extract _name##_extracts[] = { BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_DST_REG, 3, DST_REG), BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ROT_PARAM_SRC_REG, 0, SRC_REG), BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ROT_PARAM_WIDTH, 32), };
#define BPF_JIT_ROT_PATTERN(_len, _name, _shift1, _shift2, _mask, _swap) \
	BPF_JIT_FORM_PATTERN_INIT((_len), _name##_checks, _name##_extracts, bpf_jit_finalize_rotate, BPF_JIT_ROT_POST_ARG((_shift1), (_shift2), (_mask), (_swap)))

BPF_JIT_ROT_INPLACE_PATTERN_DECL(bpf_jit_rotate32_inplace, BPF_ALU, 32);
BPF_JIT_ROT_INPLACE_PATTERN_DECL(bpf_jit_rotate64_inplace, BPF_ALU64, 64);
BPF_JIT_ROT_TWOCOPY_PATTERN_DECL(bpf_jit_rotate64_twocopy, 64);
BPF_JIT_ROT_MASKED_INPLACE_PATTERN_DECL(bpf_jit_rotate32_masked_inplace);
BPF_JIT_ROT_MASKED_TWOCOPY_PATTERN_DECL(bpf_jit_rotate32_masked_twocopy);

static const struct bpf_jit_form_pattern bpf_jit_rotate_patterns[] = {
	BPF_JIT_ROT_PATTERN(4, bpf_jit_rotate32_inplace, 1, 2,
			    BPF_JIT_ROT_POST_NO_MASK, true),
	BPF_JIT_ROT_PATTERN(4, bpf_jit_rotate64_inplace, 1, 2,
			    BPF_JIT_ROT_POST_NO_MASK, true),
	BPF_JIT_ROT_PATTERN(5, bpf_jit_rotate64_twocopy, 1, 3,
			    BPF_JIT_ROT_POST_NO_MASK, false),
	BPF_JIT_ROT_PATTERN(5, bpf_jit_rotate32_masked_inplace, 2, 3, 1, true),
	BPF_JIT_ROT_PATTERN(6, bpf_jit_rotate32_masked_twocopy, 2, 4, 1, false),
};

static bool bpf_jit_alu_insn_linearizable(const struct bpf_insn *insn,
					  bool is_32bit)
{
	u8 cls = is_32bit ? BPF_ALU : BPF_ALU64;
	u8 op = BPF_OP(insn->code);

	if (BPF_CLASS(insn->code) != cls || op == BPF_END)
		return false;

	switch (op) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
	case BPF_MUL:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
	case BPF_NEG:
		return insn->off == 0;
	case BPF_DIV:
	case BPF_MOD:
		return is_32bit ? insn->off == 0 : true;
	case BPF_MOV:
		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm)
				return false;
			if (!is_32bit &&
			    (insn_is_cast_user(insn) ||
			     insn_is_mov_percpu_addr(insn)))
				return false;
			return insn->off == 0 || insn->off == 8 ||
			       insn->off == 16 ||
			       (!is_32bit && insn->off == 32);
		}
		return insn->off == 0;
	default:
		return false;
	}
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
	return bpf_jit_validate_form_patterns(insns, insn_cnt, rule,
					      bpf_jit_rotate_patterns,
					      ARRAY_SIZE(bpf_jit_rotate_patterns),
					      params);
}

struct bpf_jit_bitfield_extract_desc {
	u8 dst_reg;
	u8 src_reg;
	u32 shift;
	s64 mask;
	u8 width;
	bool mask_first;
};

static u64 bpf_jit_bitfield_mask_from_imm(s32 mask, u32 width)
{
	if (width == 32)
		return (u32)mask;

	return (u64)(s64)mask;
}

static u64 bpf_jit_bitfield_low_mask(u32 width)
{
	if (width >= 64)
		return ~0ULL;

	return (1ULL << width) - 1;
}

static bool bpf_jit_bitfield_low_mask_width(u64 mask, u32 *field_width)
{
	u32 width = 0;

	if (!mask)
		return false;

	while (mask & 1) {
		width++;
		mask >>= 1;
	}
	if (mask)
		return false;

	if (field_width)
		*field_width = width;
	return true;
}

static bool
bpf_jit_normalize_bitfield_extract_desc(struct bpf_jit_bitfield_extract_desc *desc)
{
	u64 effective_mask;
	u32 field_width;

	effective_mask = bpf_jit_bitfield_mask_from_imm((s32)desc->mask,
							desc->width);
	if (desc->mask_first)
		effective_mask >>= desc->shift;

	effective_mask &= bpf_jit_bitfield_low_mask(desc->width - desc->shift);
	if (!bpf_jit_bitfield_low_mask_width(effective_mask, &field_width))
		return false;
	if (desc->shift + field_width > desc->width)
		return false;

	desc->mask = (s64)effective_mask;
	desc->mask_first = false;
	return true;
}

static bool
bpf_jit_finalize_bitfield_extract(const struct bpf_insn *site,
				  const struct bpf_jit_rule *rule,
				  const struct bpf_jit_form_pattern *pattern,
				  struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_bitfield_extract_desc desc = {
		.dst_reg = bpf_jit_param_reg(params, BPF_JIT_BFX_PARAM_DST_REG),
		.src_reg = bpf_jit_param_reg(params, BPF_JIT_BFX_PARAM_SRC_REG),
		.shift = (u32)bpf_jit_param_imm(params, BPF_JIT_BFX_PARAM_SHIFT),
		.mask = bpf_jit_param_imm(params, BPF_JIT_BFX_PARAM_MASK),
		.width = (u8)bpf_jit_param_imm(params, BPF_JIT_BFX_PARAM_WIDTH),
		.mask_first = !!pattern->post_arg,
	};

	(void)site;
	(void)rule;

	if (!bpf_jit_normalize_bitfield_extract_desc(&desc))
		return false;

	bpf_jit_param_set_imm(params, BPF_JIT_BFX_PARAM_MASK, desc.mask);
	return true;
}

#define BPF_JIT_BFX_MOV_PATTERN_DECL(_name, _width, _first, _second,	\
				     _shift_insn, _mask_insn, _mask_first)	\
static const struct bpf_jit_pattern_check _name##_checks[] = {		\
	BPF_JIT_PATTERN_EQ(0, CODE, ((_width) == 64 ?			\
				     (BPF_ALU64 | BPF_MOV | BPF_X) :	\
				     (BPF_ALU | BPF_MOV | BPF_X))),	\
	BPF_JIT_PATTERN_EQ(0, OFF, 0),					\
	BPF_JIT_PATTERN_EQ(0, IMM, 0),					\
	BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0),				\
	BPF_JIT_PATTERN_EQ(1, CODE, (_first)),				\
	BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0),			\
	BPF_JIT_PATTERN_EQ(1, OFF, 0),					\
	BPF_JIT_PATTERN_EQ(2, CODE, (_second)),				\
	BPF_JIT_PATTERN_EQ_CAPTURE(2, DST_REG, 0),			\
	BPF_JIT_PATTERN_EQ(2, OFF, 0),					\
	BPF_JIT_PATTERN_RANGE((_shift_insn), IMM, 0, (_width) - 1),	\
};									\
static const struct bpf_jit_pattern_extract _name##_extracts[] = {	\
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_BFX_PARAM_DST_REG, 0, DST_REG), \
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_BFX_PARAM_SRC_REG, 0, SRC_REG), \
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_BFX_PARAM_SHIFT, (_shift_insn), IMM), \
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_BFX_PARAM_MASK, (_mask_insn), IMM), \
	BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_BFX_PARAM_WIDTH, (_width)),	\
};

#define BPF_JIT_BFX_INPLACE_PATTERN_DECL(_name, _width, _first, _second,	\
					 _shift_insn, _mask_insn, _mask_first) \
static const struct bpf_jit_pattern_check _name##_checks[] = {		\
	BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0),				\
	BPF_JIT_PATTERN_EQ(0, CODE, (_first)),				\
	BPF_JIT_PATTERN_EQ(0, OFF, 0),					\
	BPF_JIT_PATTERN_EQ(1, CODE, (_second)),				\
	BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0),			\
	BPF_JIT_PATTERN_EQ(1, OFF, 0),					\
	BPF_JIT_PATTERN_RANGE((_shift_insn), IMM, 0, (_width) - 1),	\
};									\
static const struct bpf_jit_pattern_extract _name##_extracts[] = {	\
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_BFX_PARAM_DST_REG, 0, DST_REG), \
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_BFX_PARAM_SRC_REG, 0, DST_REG), \
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_BFX_PARAM_SHIFT, (_shift_insn), IMM), \
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_BFX_PARAM_MASK, (_mask_insn), IMM), \
	BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_BFX_PARAM_WIDTH, (_width)),	\
};

BPF_JIT_BFX_MOV_PATTERN_DECL(bpf_jit_bfx64_mov_rsh_and, 64,
			     BPF_ALU64 | BPF_RSH | BPF_K,
			     BPF_ALU64 | BPF_AND | BPF_K, 1, 2, false);
BPF_JIT_BFX_MOV_PATTERN_DECL(bpf_jit_bfx64_mov_and_rsh, 64,
			     BPF_ALU64 | BPF_AND | BPF_K,
			     BPF_ALU64 | BPF_RSH | BPF_K, 2, 1, true);
BPF_JIT_BFX_INPLACE_PATTERN_DECL(bpf_jit_bfx64_inplace_rsh_and, 64,
				 BPF_ALU64 | BPF_RSH | BPF_K,
				 BPF_ALU64 | BPF_AND | BPF_K, 0, 1, false);
BPF_JIT_BFX_INPLACE_PATTERN_DECL(bpf_jit_bfx64_inplace_and_rsh, 64,
				 BPF_ALU64 | BPF_AND | BPF_K,
				 BPF_ALU64 | BPF_RSH | BPF_K, 1, 0, true);
BPF_JIT_BFX_MOV_PATTERN_DECL(bpf_jit_bfx32_mov_rsh_and, 32,
			     BPF_ALU | BPF_RSH | BPF_K,
			     BPF_ALU | BPF_AND | BPF_K, 1, 2, false);
BPF_JIT_BFX_MOV_PATTERN_DECL(bpf_jit_bfx32_mov_and_rsh, 32,
			     BPF_ALU | BPF_AND | BPF_K,
			     BPF_ALU | BPF_RSH | BPF_K, 2, 1, true);
BPF_JIT_BFX_INPLACE_PATTERN_DECL(bpf_jit_bfx32_inplace_rsh_and, 32,
				 BPF_ALU | BPF_RSH | BPF_K,
				 BPF_ALU | BPF_AND | BPF_K, 0, 1, false);
BPF_JIT_BFX_INPLACE_PATTERN_DECL(bpf_jit_bfx32_inplace_and_rsh, 32,
				 BPF_ALU | BPF_AND | BPF_K,
				 BPF_ALU | BPF_RSH | BPF_K, 1, 0, true);

static const struct bpf_jit_form_pattern bpf_jit_bitfield_extract_patterns[] = {
	BPF_JIT_FORM_PATTERN_INIT(3, bpf_jit_bfx64_mov_rsh_and_checks,
				  bpf_jit_bfx64_mov_rsh_and_extracts,
				  bpf_jit_finalize_bitfield_extract, false),
	BPF_JIT_FORM_PATTERN_INIT(3, bpf_jit_bfx64_mov_and_rsh_checks,
				  bpf_jit_bfx64_mov_and_rsh_extracts,
				  bpf_jit_finalize_bitfield_extract, true),
	BPF_JIT_FORM_PATTERN_INIT(2, bpf_jit_bfx64_inplace_rsh_and_checks,
				  bpf_jit_bfx64_inplace_rsh_and_extracts,
				  bpf_jit_finalize_bitfield_extract, false),
	BPF_JIT_FORM_PATTERN_INIT(2, bpf_jit_bfx64_inplace_and_rsh_checks,
				  bpf_jit_bfx64_inplace_and_rsh_extracts,
				  bpf_jit_finalize_bitfield_extract, true),
	BPF_JIT_FORM_PATTERN_INIT(3, bpf_jit_bfx32_mov_rsh_and_checks,
				  bpf_jit_bfx32_mov_rsh_and_extracts,
				  bpf_jit_finalize_bitfield_extract, false),
	BPF_JIT_FORM_PATTERN_INIT(3, bpf_jit_bfx32_mov_and_rsh_checks,
				  bpf_jit_bfx32_mov_and_rsh_extracts,
				  bpf_jit_finalize_bitfield_extract, true),
	BPF_JIT_FORM_PATTERN_INIT(2, bpf_jit_bfx32_inplace_rsh_and_checks,
				  bpf_jit_bfx32_inplace_rsh_and_extracts,
				  bpf_jit_finalize_bitfield_extract, false),
	BPF_JIT_FORM_PATTERN_INIT(2, bpf_jit_bfx32_inplace_and_rsh_checks,
				  bpf_jit_bfx32_inplace_and_rsh_extracts,
				  bpf_jit_finalize_bitfield_extract, true),
};

static bool
bpf_jit_validate_bitfield_extract_rule(const struct bpf_insn *insns,
				       u32 insn_cnt,
				       const struct bpf_jit_rule *rule,
				       struct bpf_jit_canonical_params *params)
{
	return bpf_jit_validate_form_patterns(insns, insn_cnt, rule,
					      bpf_jit_bitfield_extract_patterns,
					      ARRAY_SIZE(bpf_jit_bitfield_extract_patterns),
					      params);
}

static const struct bpf_jit_pattern_check bpf_jit_addr_calc_checks[] = {
	BPF_JIT_PATTERN_EQ(0, CODE, BPF_ALU64 | BPF_MOV | BPF_X),
	BPF_JIT_PATTERN_EQ(0, OFF, 0),
	BPF_JIT_PATTERN_EQ(0, IMM, 0),
	BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0),
	BPF_JIT_PATTERN_EQ(1, CODE, BPF_ALU64 | BPF_LSH | BPF_K),
	BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0),
	BPF_JIT_PATTERN_RANGE(1, IMM, 1, 3),
	BPF_JIT_PATTERN_EQ(2, CODE, BPF_ALU64 | BPF_ADD | BPF_X),
	BPF_JIT_PATTERN_EQ_CAPTURE(2, DST_REG, 0),
	BPF_JIT_PATTERN_EQ(2, OFF, 0),
	BPF_JIT_PATTERN_EQ(2, IMM, 0),
	BPF_JIT_PATTERN_NE_CAPTURE(2, SRC_REG, 0),
};

static const struct bpf_jit_pattern_extract bpf_jit_addr_calc_extracts[] = {
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ACALC_PARAM_DST_REG, 0, DST_REG),
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ACALC_PARAM_BASE_REG, 2, SRC_REG),
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ACALC_PARAM_INDEX_REG, 0, SRC_REG),
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_ACALC_PARAM_SCALE, 1, IMM),
};

static const struct bpf_jit_form_pattern bpf_jit_addr_calc_patterns[] = {
	{
		.site_len = 3,
		.checks = bpf_jit_addr_calc_checks,
		.nr_checks = ARRAY_SIZE(bpf_jit_addr_calc_checks),
		.extracts = bpf_jit_addr_calc_extracts,
		.nr_extracts = ARRAY_SIZE(bpf_jit_addr_calc_extracts),
	},
};

static bool
bpf_jit_validate_addr_calc_rule(const struct bpf_insn *insns,
				u32 insn_cnt,
				const struct bpf_jit_rule *rule,
				struct bpf_jit_canonical_params *params)
{
	return bpf_jit_validate_form_patterns(insns, insn_cnt, rule,
					      bpf_jit_addr_calc_patterns,
					      ARRAY_SIZE(bpf_jit_addr_calc_patterns),
					      params);
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

static bool
bpf_jit_finalize_endian_load(const struct bpf_insn *site,
			     const struct bpf_jit_rule *rule,
			     const struct bpf_jit_form_pattern *pattern,
			     struct bpf_jit_canonical_params *params)
{
	s32 width_bits;

	(void)rule;
	(void)pattern;

	width_bits = bpf_jit_endian_width_from_mem_opcode(site[0].code);
	if (width_bits <= 0 || BPF_CLASS(site[0].code) != BPF_LDX)
		return false;
	if (!bpf_jit_endian_fusion_is_swap(&site[1], width_bits))
		return false;

	bpf_jit_param_set_imm(params, BPF_JIT_ENDIAN_PARAM_WIDTH, width_bits);
	return true;
}

static bool
bpf_jit_finalize_endian_store(const struct bpf_insn *site,
			      const struct bpf_jit_rule *rule,
			      const struct bpf_jit_form_pattern *pattern,
			      struct bpf_jit_canonical_params *params)
{
	s32 width_bits;

	(void)rule;
	(void)pattern;

	width_bits = bpf_jit_endian_width_from_mem_opcode(site[1].code);
	if (width_bits <= 0 || BPF_CLASS(site[1].code) != BPF_STX)
		return false;
	if (!bpf_jit_endian_fusion_is_swap(&site[0], width_bits))
		return false;

	bpf_jit_param_set_imm(params, BPF_JIT_ENDIAN_PARAM_WIDTH, width_bits);
	return true;
}

static const struct bpf_jit_pattern_check bpf_jit_endian_load_checks[] = {
	BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0),
	BPF_JIT_PATTERN_EQ(0, IMM, 0),
	BPF_JIT_PATTERN_EQ_CAPTURE(1, DST_REG, 0),
};

static const struct bpf_jit_pattern_extract bpf_jit_endian_load_extracts[] = {
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ENDIAN_PARAM_DATA_REG, 0, DST_REG),
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ENDIAN_PARAM_BASE_REG, 0, SRC_REG),
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_ENDIAN_PARAM_OFFSET, 0, OFF),
	BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ENDIAN_PARAM_DIRECTION,
				  BPF_JIT_ENDIAN_LOAD_SWAP),
};

static const struct bpf_jit_pattern_check bpf_jit_endian_store_checks[] = {
	BPF_JIT_PATTERN_CAPTURE(0, DST_REG, 0),
	BPF_JIT_PATTERN_EQ(1, IMM, 0),
	BPF_JIT_PATTERN_EQ_CAPTURE(1, SRC_REG, 0),
};

static const struct bpf_jit_pattern_extract bpf_jit_endian_store_extracts[] = {
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ENDIAN_PARAM_DATA_REG, 0, DST_REG),
	BPF_JIT_PATTERN_EXTRACT_REG(BPF_JIT_ENDIAN_PARAM_BASE_REG, 1, DST_REG),
	BPF_JIT_PATTERN_EXTRACT_IMM(BPF_JIT_ENDIAN_PARAM_OFFSET, 1, OFF),
	BPF_JIT_PATTERN_CONST_IMM(BPF_JIT_ENDIAN_PARAM_DIRECTION,
				  BPF_JIT_ENDIAN_SWAP_STORE),
};

static const struct bpf_jit_form_pattern bpf_jit_endian_fusion_patterns[] = {
	{
		.site_len = 2,
		.checks = bpf_jit_endian_load_checks,
		.nr_checks = ARRAY_SIZE(bpf_jit_endian_load_checks),
		.extracts = bpf_jit_endian_load_extracts,
		.nr_extracts = ARRAY_SIZE(bpf_jit_endian_load_extracts),
		.post = bpf_jit_finalize_endian_load,
	},
	{
		.site_len = 2,
		.checks = bpf_jit_endian_store_checks,
		.nr_checks = ARRAY_SIZE(bpf_jit_endian_store_checks),
		.extracts = bpf_jit_endian_store_extracts,
		.nr_extracts = ARRAY_SIZE(bpf_jit_endian_store_extracts),
		.post = bpf_jit_finalize_endian_store,
	},
};

static bool
bpf_jit_validate_endian_fusion_rule(const struct bpf_insn *insns,
				    u32 insn_cnt,
				    const struct bpf_jit_rule *rule,
				    struct bpf_jit_canonical_params *params)
{
	return bpf_jit_validate_form_patterns(insns, insn_cnt, rule,
					      bpf_jit_endian_fusion_patterns,
					      ARRAY_SIZE(bpf_jit_endian_fusion_patterns),
					      params);
}

#undef BPF_JIT_FORM_PATTERN_INIT
#undef BPF_JIT_BFX_INPLACE_PATTERN_DECL
#undef BPF_JIT_BFX_MOV_PATTERN_DECL

static bool bpf_jit_branch_flip_body_linear(const struct bpf_insn *insns,
					    u32 start, u32 len)
{
	u32 i;

	if (!len)
		return false;

	for (i = start; i < start + len; i++) {
		const struct bpf_insn *insn = &insns[i];
		u8 cls = BPF_CLASS(insn->code);
		u8 mode = BPF_MODE(insn->code);
		u8 size = BPF_SIZE(insn->code);

		if ((cls == BPF_ALU || cls == BPF_ALU64) &&
		    bpf_jit_alu_insn_linearizable(insn, cls == BPF_ALU))
			continue;
		if (insn->code == (BPF_ALU | BPF_END | BPF_FROM_BE) ||
		    insn->code == (BPF_ALU | BPF_END | BPF_FROM_LE) ||
		    insn->code == (BPF_ALU64 | BPF_END | BPF_FROM_LE))
			continue;
		if (cls == BPF_LDX && mode == BPF_MEM &&
		    (size == BPF_B || size == BPF_H ||
		     size == BPF_W || size == BPF_DW))
			continue;
		if (cls == BPF_LDX && mode == BPF_MEMSX &&
		    (size == BPF_B || size == BPF_H || size == BPF_W))
			continue;

		return false;
	}

	return true;
}

#define BPF_JIT_BRANCH_FLIP_X86_MAX_NATIVE_BYTES	(128U + 64U)
#define BPF_JIT_BRANCH_FLIP_X86_MAX_COND_JUMP_BYTES	6U
#define BPF_JIT_BRANCH_FLIP_X86_MAX_JUMP_BYTES		5U

static bool bpf_jit_imm8(s32 imm)
{
	return imm >= -128 && imm <= 127;
}

static u32 bpf_jit_branch_flip_x86_cmp_max_native_bytes(
	const struct bpf_insn *jcc)
{
	if (BPF_SRC(jcc->code) == BPF_X)
		return 3;

	if (BPF_OP(jcc->code) == BPF_JSET)
		return 7;

	if (!jcc->imm)
		return 3;

	return bpf_jit_imm8(jcc->imm) ? 4 : 7;
}

static u32 bpf_jit_branch_flip_x86_insn_max_native_bytes(
	const struct bpf_insn *insn)
{
	u8 cls = BPF_CLASS(insn->code);
	u8 op = BPF_OP(insn->code);
	u8 src = BPF_SRC(insn->code);

	if (cls == BPF_ALU) {
		switch (op) {
		case BPF_ADD:
		case BPF_SUB:
		case BPF_AND:
		case BPF_OR:
		case BPF_XOR:
			return src == BPF_X ? 3 : (bpf_jit_imm8(insn->imm) ? 4 : 7);
		case BPF_NEG:
			return 3;
		case BPF_MOV:
			return src == BPF_X ? 4 : 7;
		case BPF_MUL:
			return src == BPF_X ? 4 : (bpf_jit_imm8(insn->imm) ? 4 : 7);
		case BPF_LSH:
		case BPF_RSH:
		case BPF_ARSH:
			return src == BPF_X ? 12 : 4;
		case BPF_DIV:
		case BPF_MOD:
			return 22;
		default:
			return 0;
		}
	}

	if (cls == BPF_ALU64) {
		switch (op) {
		case BPF_ADD:
		case BPF_SUB:
		case BPF_AND:
		case BPF_OR:
		case BPF_XOR:
			return src == BPF_X ? 3 : (bpf_jit_imm8(insn->imm) ? 4 : 7);
		case BPF_NEG:
			return 3;
		case BPF_MOV:
			return src == BPF_X ? 4 : 7;
		case BPF_MUL:
			return src == BPF_X ? 4 : (bpf_jit_imm8(insn->imm) ? 4 : 7);
		case BPF_LSH:
		case BPF_RSH:
		case BPF_ARSH:
			return src == BPF_X ? 12 : 4;
		case BPF_DIV:
		case BPF_MOD:
			return 22;
		default:
			return 0;
		}
	}

	if (insn->code == (BPF_ALU | BPF_END | BPF_FROM_BE) ||
	    insn->code == (BPF_ALU | BPF_END | BPF_FROM_LE) ||
	    insn->code == (BPF_ALU64 | BPF_END | BPF_FROM_LE))
		return 9;

	if (cls == BPF_LDX)
		return 8;

	return 0;
}

static bool bpf_jit_branch_flip_x86_body_native_bytes(const struct bpf_insn *insns,
						      u32 start, u32 len,
						      u32 *out_bytes)
{
	u32 total = 0;
	u32 i;

	for (i = start; i < start + len; i++) {
		u32 insn_bytes;

		insn_bytes = bpf_jit_branch_flip_x86_insn_max_native_bytes(&insns[i]);
		if (!insn_bytes)
			return false;
		if (check_add_overflow(total, insn_bytes, &total))
			return false;
	}

	if (out_bytes)
		*out_bytes = total;

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
	u32 body_a_native_bytes, body_b_native_bytes, native_bytes;
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
	if (!bpf_jit_branch_flip_x86_body_native_bytes(insns, body_a_start,
						       body_a_len,
						       &body_a_native_bytes) ||
	    !bpf_jit_branch_flip_x86_body_native_bytes(insns, body_b_start,
						       body_b_len,
						       &body_b_native_bytes))
		return false;

	native_bytes = bpf_jit_branch_flip_x86_cmp_max_native_bytes(jcc);
	if (check_add_overflow(native_bytes, body_a_native_bytes, &native_bytes) ||
	    check_add_overflow(native_bytes, body_b_native_bytes, &native_bytes) ||
	    check_add_overflow(native_bytes,
			       BPF_JIT_BRANCH_FLIP_X86_MAX_COND_JUMP_BYTES,
			       &native_bytes) ||
	    check_add_overflow(native_bytes,
			       BPF_JIT_BRANCH_FLIP_X86_MAX_JUMP_BYTES,
			       &native_bytes))
		return false;
	if (native_bytes > BPF_JIT_BRANCH_FLIP_X86_MAX_NATIVE_BYTES)
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

static bool bpf_jit_branch_flip_cond_op_valid(u8 op)
{
	return op == BPF_JSET || bpf_jit_cond_op_valid(op);
}

struct bpf_jit_form_meta {
	const char *name;
	unsigned long native_choice_mask;
	bool allow_side_effects;
	bool (*validate)(const struct bpf_insn *insns, u32 insn_cnt,
			 const struct bpf_jit_rule *rule,
			 struct bpf_jit_canonical_params *params);
};

__weak bool bpf_jit_arch_form_supported(u16 canonical_form, u16 native_choice)
{
	return false;
}

static const struct bpf_jit_form_meta bpf_jit_form_meta[] = {
	[BPF_JIT_CF_ROTATE] = {
		.name = "rotate",
		.native_choice_mask = BIT(BPF_JIT_ROT_ROR) |
				      BIT(BPF_JIT_ROT_RORX),
		.validate = bpf_jit_validate_rotate_rule,
	},
	[BPF_JIT_CF_WIDE_MEM] = {
		.name = "wide_mem",
		.native_choice_mask = BIT(BPF_JIT_WMEM_WIDE_LOAD),
		.validate = bpf_jit_validate_wide_mem_rule,
	},
	[BPF_JIT_CF_ADDR_CALC] = {
		.name = "addr_calc",
		.native_choice_mask = BIT(BPF_JIT_ACALC_LEA),
		.validate = bpf_jit_validate_addr_calc_rule,
	},
	[BPF_JIT_CF_COND_SELECT] = {
		.name = "cond_select",
		.native_choice_mask = BIT(BPF_JIT_SEL_CMOVCC),
		.validate = bpf_jit_validate_cond_select_rule,
	},
	[BPF_JIT_CF_BITFIELD_EXTRACT] = {
		.name = "bitfield_extract",
		.native_choice_mask = BIT(BPF_JIT_BFX_EXTRACT),
		.validate = bpf_jit_validate_bitfield_extract_rule,
	},
	[BPF_JIT_CF_ENDIAN_FUSION] = {
		.name = "endian_fusion",
		.native_choice_mask = BIT(BPF_JIT_ENDIAN_MOVBE),
		.allow_side_effects = true,
		.validate = bpf_jit_validate_endian_fusion_rule,
	},
	[BPF_JIT_CF_BRANCH_FLIP] = {
		.name = "branch_flip",
		.native_choice_mask = BIT(BPF_JIT_BFLIP_FLIPPED),
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

bool bpf_jit_pattern_rule_shape_valid(const struct bpf_jit_rule *rule)
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

bool bpf_jit_validate_rule(const struct bpf_prog *prog,
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
	if (!bpf_jit_arch_form_supported(rule->canonical_form,
					 rule->native_choice)) {
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
