// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF JIT directive/policy framework
 *
 * v2 (BPF_PROG_LOAD path): cmov_select via jit_directives_fd
 * v4 (BPF_PROG_JIT_RECOMPILE path): general rewrite rule framework
 */
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
#include <uapi/linux/fcntl.h>
#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#endif

#define BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE SZ_64K
#define BPF_JIT_MAX_RULES		256

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

static bool bpf_pseudo_call_insn(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}

/* ================================================================
 * v2 legacy path (BPF_PROG_LOAD with jit_directives_fd)
 * ================================================================ */

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

	if (!bpf_jit_is_cmov_cond_jump(jmp_insn) || bpf_jmp_offset((struct bpf_insn *)jmp_insn) != 2)
		return false;
	if (!bpf_jit_is_simple_mov(fallthrough_insn) || !bpf_jit_is_simple_mov(target_insn))
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

	if (!bpf_jit_is_simple_mov(default_insn) || !bpf_jit_is_simple_mov(override_insn))
		return false;
	if (!bpf_jit_is_cmov_cond_jump(jmp_insn) || bpf_jmp_offset((struct bpf_insn *)jmp_insn) != 1)
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

static bool bpf_jit_cmov_select_find_region(const struct bpf_insn *insns, u32 insn_cnt,
					    u32 idx, u32 *start, u32 *end)
{
	if (bpf_jit_cmov_select_match_diamond(insns, insn_cnt, idx)) {
		*start = idx;
		*end = idx + 4;
		return true;
	}

	if (bpf_jit_cmov_select_match_compact(insns, insn_cnt, idx)) {
		*start = idx - 1;
		*end = idx + 2;
		return true;
	}

	return false;
}

static bool bpf_jit_cmov_select_has_interior_edge(struct bpf_verifier_env *env,
						  u32 start, u32 end)
{
	u32 i, j;

	for (i = 0; i < env->prog->len; i++) {
		struct bpf_iarray *succ;

		if (i >= start && i < end)
			continue;

		succ = bpf_insn_successors(env, i);
		for (j = 0; j < succ->cnt; j++) {
			u32 target = succ->items[j];

			if (target > start && target < end)
				return true;
		}
	}

	return false;
}

static int bpf_jit_find_site_insn_idx(const struct bpf_verifier_env *env, u32 orig_idx)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		if (env->insn_aux_data[i].orig_idx == orig_idx)
			return i;
	}

	return -ENOENT;
}

static bool bpf_jit_directive_conflicts(const struct bpf_jit_directive_state *state,
					u32 rec_idx, u32 subprog_idx, u32 insn_idx)
{
	u32 i;

	for (i = 0; i < rec_idx; i++) {
		const struct bpf_jit_directive *other = &state->recs[i];

		if (!(other->flags & BPF_JIT_DIRECTIVE_F_VALIDATED))
			continue;
		if (other->kind != state->recs[rec_idx].kind)
			continue;
		if (other->subprog_idx == subprog_idx && other->insn_idx == insn_idx)
			return true;
	}

	return false;
}

static int bpf_jit_directive_validate_payload(const struct bpf_jit_directive_rec *rec)
{
	struct bpf_jit_directive_cmov_select payload;

	switch (rec->kind) {
	case BPF_JIT_DIRECTIVE_CMOV_SELECT:
		memcpy(&payload, &rec->payload, sizeof(payload));
		if (payload.flags || payload.reserved)
			return -EINVAL;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int bpf_jit_directive_validate_rec(const struct bpf_jit_directive_rec *rec,
					  u32 insn_cnt)
{
	if (rec->reserved || rec->site_idx >= insn_cnt)
		return -EINVAL;

	return bpf_jit_directive_validate_payload(rec);
}

struct bpf_jit_directive_state *
bpf_jit_directives_load(struct bpf_prog *prog, int fd, u32 flags)
{
	const struct bpf_jit_directive_hdr *hdr;
	struct bpf_jit_directive_state *state = NULL;
	const struct bpf_jit_directive_rec *recs;
	struct fd f = fdget(fd);
	size_t blob_len, expected_len, records_len;
	void *blob = NULL;
	loff_t pos = 0;
	ssize_t nread;
	u32 i;

	if (!prog)
		return ERR_PTR(-EINVAL);

	if (flags & ~BPF_F_JIT_DIRECTIVES_LOG)
		return ERR_PTR(-EINVAL);
	if (fd_empty(f))
		return ERR_PTR(-EBADF);
	if (!bpf_jit_directives_valid_memfd(fd_file(f))) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	blob_len = i_size_read(file_inode(fd_file(f)));
	if (!blob_len) {
		fdput(f);
		return NULL;
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
	if (nread < 0) {
		state = ERR_PTR(nread);
		goto out;
	}
	if (nread != blob_len) {
		state = ERR_PTR(-EIO);
		goto out;
	}

	if (blob_len < sizeof(*hdr)) {
		state = ERR_PTR(-EINVAL);
		goto out;
	}

	hdr = blob;
	if (hdr->magic != BPF_JIT_DIRECTIVE_MAGIC ||
	    hdr->version != BPF_JIT_DIRECTIVE_VERSION ||
	    hdr->rec_size != sizeof(struct bpf_jit_directive_rec) ||
	    hdr->insn_cnt != prog->len) {
		state = ERR_PTR(-EINVAL);
		goto out;
	}

	if (check_mul_overflow((size_t)hdr->rec_cnt,
			       sizeof(struct bpf_jit_directive_rec),
			       &records_len)) {
		state = ERR_PTR(-E2BIG);
		goto out;
	}

	expected_len = sizeof(*hdr) + records_len;
	if (expected_len != blob_len) {
		state = ERR_PTR(-EINVAL);
		goto out;
	}
	if (!hdr->rec_cnt)
		goto out;

	recs = (const struct bpf_jit_directive_rec *)(hdr + 1);
	for (i = 0; i < hdr->rec_cnt; i++) {
		u32 j;
		int err;

		err = bpf_jit_directive_validate_rec(&recs[i], prog->len);
		if (err) {
			state = ERR_PTR(err);
			goto out;
		}

		for (j = 0; j < i; j++) {
			if (recs[j].kind == recs[i].kind &&
			    recs[j].site_idx == recs[i].site_idx) {
				state = ERR_PTR(-EINVAL);
				goto out;
			}
		}
	}

	state = kvmalloc(struct_size(state, recs, hdr->rec_cnt), GFP_KERNEL_ACCOUNT);
	if (!state) {
		state = ERR_PTR(-ENOMEM);
		goto out;
	}

	state->rec_cnt = hdr->rec_cnt;
	state->validated_cnt = 0;
	for (i = 0; i < hdr->rec_cnt; i++) {
		state->recs[i].kind = recs[i].kind;
		state->recs[i].flags = 0;
		state->recs[i].site_idx = recs[i].site_idx;
		state->recs[i].subprog_idx = 0;
		state->recs[i].insn_idx = 0;
		state->recs[i].payload = recs[i].payload;
	}

out:
	kvfree(blob);
	fdput(f);
	return state;
}

void bpf_jit_directives_free(struct bpf_jit_directive_state *state)
{
	kvfree(state);
}

int bpf_jit_directives_validate(struct bpf_verifier_env *env)
{
	struct bpf_jit_directive_state *state = env->prog->aux->jit_directives;
	u32 i;

	if (!state)
		return 0;

	state->validated_cnt = 0;
	for (i = 0; i < state->rec_cnt; i++) {
		struct bpf_jit_directive *rec = &state->recs[i];
		struct bpf_subprog_info *subprog;
		u32 subprog_idx;
		int insn_idx;

		rec->flags &= ~BPF_JIT_DIRECTIVE_F_VALIDATED;
		rec->subprog_idx = 0;
		rec->insn_idx = 0;

		insn_idx = bpf_jit_find_site_insn_idx(env, rec->site_idx);
		if (insn_idx < 0)
			continue;

		switch (rec->kind) {
		case BPF_JIT_DIRECTIVE_CMOV_SELECT:
		{
			u32 region_start, region_end;

			if (!bpf_jit_cmov_select_find_region(env->prog->insnsi, env->prog->len,
							     insn_idx, &region_start,
							     &region_end))
				continue;
			subprog = bpf_find_containing_subprog(env, region_start);
			if (!subprog ||
			    bpf_find_containing_subprog(env, region_end - 1) != subprog)
				continue;
			if (bpf_jit_cmov_select_has_interior_edge(env, region_start, region_end))
				continue;
			subprog_idx = subprog - env->subprog_info;
			if (bpf_jit_directive_conflicts(state, i, subprog_idx,
							insn_idx - subprog->start))
				continue;
			rec->flags |= BPF_JIT_DIRECTIVE_F_VALIDATED;
			rec->subprog_idx = subprog_idx;
			rec->insn_idx = insn_idx - subprog->start;
			state->validated_cnt++;
			break;
		}
		default:
			break;
		}
	}

	return 0;
}

const struct bpf_jit_directive *
bpf_jit_directive_lookup(const struct bpf_prog *prog, u16 kind, u32 insn_idx)
{
	const struct bpf_prog_aux *main_aux;
	const struct bpf_jit_directive_state *state;
	u32 func_idx;
	u32 i;

	if (prog->blinded)
		return NULL;

	main_aux = prog->aux->main_prog_aux ? prog->aux->main_prog_aux : prog->aux;
	state = main_aux->jit_directives;
	if (!state || !state->validated_cnt)
		return NULL;

	func_idx = prog->aux->func_idx;
	for (i = 0; i < state->rec_cnt; i++) {
		const struct bpf_jit_directive *rec = &state->recs[i];

		if (!(rec->flags & BPF_JIT_DIRECTIVE_F_VALIDATED))
			continue;
		if (rec->kind != kind)
			continue;
		if (rec->subprog_idx != func_idx || rec->insn_idx != insn_idx)
			continue;
		return rec;
	}

	return NULL;
}

/* ================================================================
 * v4 JIT rewrite rule framework (BPF_PROG_JIT_RECOMPILE path)
 * ================================================================ */

void bpf_jit_free_policy(struct bpf_jit_policy *policy)
{
	if (!policy)
		return;

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
	/* Higher priority first on tie */
	if (ra->priority > rb->priority)
		return -1;
	if (ra->priority < rb->priority)
		return 1;
	return 0;
}

static u16 bpf_jit_rule_form(const struct bpf_jit_rule *rule)
{
	if (rule->rule_kind == BPF_JIT_RK_PATTERN)
		return rule->canonical_form;

	switch (rule->rule_kind) {
	case BPF_JIT_RK_ROTATE:
		return BPF_JIT_CF_ROTATE;
	case BPF_JIT_RK_WIDE_MEM:
		return BPF_JIT_CF_WIDE_MEM;
	case BPF_JIT_RK_ADDR_CALC:
		return BPF_JIT_CF_ADDR_CALC;
	case BPF_JIT_RK_COND_SELECT:
		return BPF_JIT_CF_COND_SELECT;
	case BPF_JIT_RK_BITFIELD_EXTRACT:
		return BPF_JIT_CF_BITFIELD_EXTRACT;
	default:
		return 0;
	}
}

static bool bpf_jit_native_choice_valid(u16 form, u16 native_choice)
{
	switch (form) {
	case BPF_JIT_CF_COND_SELECT:
		return native_choice == BPF_JIT_SEL_CMOVCC ||
		       native_choice == BPF_JIT_SEL_BRANCH;
	case BPF_JIT_CF_WIDE_MEM:
		return native_choice == BPF_JIT_WMEM_WIDE_LOAD ||
		       native_choice == BPF_JIT_WMEM_BYTE_LOADS;
	case BPF_JIT_CF_ROTATE:
		return native_choice == BPF_JIT_ROT_ROR ||
		       native_choice == BPF_JIT_ROT_RORX ||
		       native_choice == BPF_JIT_ROT_SHIFT;
	case BPF_JIT_CF_ADDR_CALC:
		return native_choice == BPF_JIT_ACALC_LEA ||
		       native_choice == BPF_JIT_ACALC_SHIFT_ADD;
	case BPF_JIT_CF_BITFIELD_EXTRACT:
		return native_choice == BPF_JIT_BFX_EXTRACT;
	default:
		return false;
	}
}

static bool bpf_jit_pattern_rule_shape_valid(const struct bpf_jit_rule *rule)
{
	switch (rule->canonical_form) {
	case BPF_JIT_CF_ROTATE:
		return rule->site_len == 4 || rule->site_len == 5 ||
		       rule->site_len == 6;
	case BPF_JIT_CF_WIDE_MEM:
		return rule->site_len == 4 || rule->site_len == 7 ||
		       rule->site_len == 10 || rule->site_len == 13 ||
		       rule->site_len == 16 || rule->site_len == 19 ||
		       rule->site_len == 22;
	case BPF_JIT_CF_ADDR_CALC:
		return rule->site_len == 3;
	case BPF_JIT_CF_COND_SELECT:
		return rule->site_len == 3 || rule->site_len == 4;
	case BPF_JIT_CF_BITFIELD_EXTRACT:
		return rule->site_len == 2 || rule->site_len == 3;
	default:
		return false;
	}
}

static bool bpf_jit_compute_site_end(u32 site_start, u32 site_len, u32 *site_end)
{
	return !check_add_overflow(site_start, site_len, site_end);
}

static bool bpf_jit_site_range_valid(u32 site_start, u32 site_len,
				     u32 insn_cnt, u32 *site_end)
{
	u32 end;

	if (!bpf_jit_compute_site_end(site_start, site_len, &end))
		return false;
	if (end > insn_cnt)
		return false;

	if (site_end)
		*site_end = end;

	return true;
}

static u32 bpf_jit_cpu_features_for_native_choice(u16 form, u16 native_choice)
{
	switch (form) {
	case BPF_JIT_CF_COND_SELECT:
		return native_choice == BPF_JIT_SEL_CMOVCC ? BPF_JIT_X86_CMOV : 0;
	case BPF_JIT_CF_ROTATE:
		return native_choice == BPF_JIT_ROT_RORX ? BPF_JIT_X86_BMI2 : 0;
	default:
		return 0;
	}
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

/**
 * bpf_jit_validate_cond_select_rule - validate a COND_SELECT rule against prog
 *
 * Check that the BPF insn sequence at site_start matches either a diamond
 * (jcc+2, mov, ja+1, mov) or compact (mov, jcc+1, mov) shape, and that no
 * jump from outside the pattern targets an interior instruction (which would
 * corrupt addrs[] after the cmov transformation).
 */
static bool bpf_jit_validate_cond_select_rule(const struct bpf_insn *insns,
					      u32 insn_cnt,
					      const struct bpf_jit_rule *rule)
{
	u32 idx = rule->site_start;
	bool shape_ok;

	if (rule->site_len == 4) {
		/* Diamond: jcc+2, mov_false, ja+1, mov_true */
		shape_ok = bpf_jit_cmov_select_match_diamond(insns, insn_cnt, idx);
	} else if (rule->site_len == 3) {
		/* Compact: mov_default, jcc+1, mov_override
		 * The match function expects idx pointing at the jcc,
		 * so idx+1 is the jcc in a compact form where site_start
		 * is the mov_default.
		 */
		shape_ok = bpf_jit_cmov_select_match_compact(insns, insn_cnt, idx + 1);
	} else {
		return false;
	}

	if (!shape_ok)
		return false;

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
		return false;

	return true;
}

struct bpf_jit_wide_mem_shape {
	u8 dst_reg;
	u8 base_reg;
	s16 base_off;
	u8 width;
	bool big_endian;
};

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
static bool bpf_jit_validate_wide_mem_rule(const struct bpf_insn *insns,
					   u32 insn_cnt,
					   const struct bpf_jit_rule *rule)
{
	if (!bpf_jit_parse_wide_mem_shape(insns, insn_cnt, rule->site_start,
					  rule->site_len, NULL))
		return false;

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
		return false;

	return true;
}

/**
 * bpf_jit_validate_rotate_4insn - validate a 4-insn rotate idiom
 *
 * Classic pattern (mov+lsh+rsh+or):
 *   [0] mov   tmp, dst        (copy original)
 *   [1] lsh   dst, N          (left shift by rotation amount)
 *   [2] rsh   tmp, (W-N)      (right shift complement)
 *   [3] or    dst, tmp        (combine)
 *
 * Commuted pattern (mov+rsh+lsh+or) — clang often generates this:
 *   [0] mov   tmp, dst        (copy original)
 *   [1] rsh   tmp, (W-N)      (right shift complement on tmp)
 *   [2] lsh   dst, N          (left shift on original)
 *   [3] or    dst, tmp        (combine)
 *
 * Where W is 32 or 64 and N is the rotation amount (1..W-1).
 */
static bool bpf_jit_validate_rotate_4insn(const struct bpf_insn *insns,
					   u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *mov_insn, *insn1, *insn2, *or_insn;
	const struct bpf_insn *lsh_insn, *rsh_insn;
	u8 lsh_cls, rsh_cls, or_cls;
	u32 width, rot_amount;
	bool commuted;

	if (idx + 4 > insn_cnt)
		return false;

	mov_insn = &insns[idx];
	insn1    = &insns[idx + 1];
	insn2    = &insns[idx + 2];
	or_insn  = &insns[idx + 3];

	/* [0] Must be MOV_X (reg-to-reg copy) */
	if (BPF_OP(mov_insn->code) != BPF_MOV ||
	    BPF_SRC(mov_insn->code) != BPF_X ||
	    mov_insn->off != 0 || mov_insn->imm != 0)
		return false;

	/* Determine width from MOV class */
	if (BPF_CLASS(mov_insn->code) == BPF_ALU64)
		width = 64;
	else if (BPF_CLASS(mov_insn->code) == BPF_ALU)
		width = 32;
	else
		return false;

	/* The temporary must stay distinct from the rotate destination. */
	if (mov_insn->dst_reg == mov_insn->src_reg)
		return false;

	/*
	 * Detect ordering: classic (lsh+rsh) or commuted (rsh+lsh).
	 * Check insn1: if it's LSH, classic; if RSH, commuted.
	 */
	if (BPF_OP(insn1->code) == BPF_LSH && BPF_SRC(insn1->code) == BPF_K) {
		commuted = false;
		lsh_insn = insn1;
		rsh_insn = insn2;
	} else if (BPF_OP(insn1->code) == BPF_RSH && BPF_SRC(insn1->code) == BPF_K) {
		commuted = true;
		rsh_insn = insn1;
		lsh_insn = insn2;
	} else {
		return false;
	}

	/* Validate LSH instruction */
	lsh_cls = BPF_CLASS(lsh_insn->code);
	if (BPF_OP(lsh_insn->code) != BPF_LSH || BPF_SRC(lsh_insn->code) != BPF_K)
		return false;
	if ((width == 64 && lsh_cls != BPF_ALU64) ||
	    (width == 32 && lsh_cls != BPF_ALU))
		return false;
	if (lsh_insn->off != 0)
		return false;
	/* lsh dst must be the original src register */
	if (lsh_insn->dst_reg != mov_insn->src_reg)
		return false;

	rot_amount = (u32)lsh_insn->imm;
	if (rot_amount == 0 || rot_amount >= width)
		return false;

	/* Validate RSH instruction */
	rsh_cls = BPF_CLASS(rsh_insn->code);
	if (BPF_OP(rsh_insn->code) != BPF_RSH || BPF_SRC(rsh_insn->code) != BPF_K)
		return false;
	if ((width == 64 && rsh_cls != BPF_ALU64) ||
	    (width == 32 && rsh_cls != BPF_ALU))
		return false;
	if (rsh_insn->off != 0)
		return false;
	/* rsh dst must be the tmp register */
	if (rsh_insn->dst_reg != mov_insn->dst_reg)
		return false;
	if ((u32)rsh_insn->imm != width - rot_amount)
		return false;

	/* [3] or dst, tmp */
	or_cls = BPF_CLASS(or_insn->code);
	if (BPF_OP(or_insn->code) != BPF_OR || BPF_SRC(or_insn->code) != BPF_X)
		return false;
	if ((width == 64 && or_cls != BPF_ALU64) ||
	    (width == 32 && or_cls != BPF_ALU))
		return false;
	if (or_insn->off != 0 || or_insn->imm != 0)
		return false;
	if (or_insn->dst_reg != mov_insn->src_reg)
		return false;
	if (or_insn->src_reg != mov_insn->dst_reg)
		return false;

	(void)commuted; /* both orderings produce the same result */
	return true;
}

/**
 * bpf_jit_validate_rotate_5insn - validate a 5-insn two-copy rotate
 *
 * clang often generates this pattern for 64-bit rotates:
 *   [0] mov64  tmp, src       (copy for right-shift path)
 *   [1] rsh64  tmp, (W-N)     (right shift complement)
 *   [2] mov64  dst, src       (copy for left-shift path, same src as [0])
 *   [3] lsh64  dst, N         (left shift)
 *   [4] or64   dst, tmp       (combine)
 *
 * Where W is 64 and N is the rotation amount (1..63).
 * Result register is dst (insns[idx+2].dst_reg).
 */
static bool bpf_jit_validate_rotate_5insn(const struct bpf_insn *insns,
					   u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *mov1, *rsh_insn, *mov2, *lsh_insn, *or_insn;
	u32 rot_amount, rsh_amount;

	if (idx + 5 > insn_cnt)
		return false;

	mov1     = &insns[idx];
	rsh_insn = &insns[idx + 1];
	mov2     = &insns[idx + 2];
	lsh_insn = &insns[idx + 3];
	or_insn  = &insns[idx + 4];

	/* [0] mov64 tmp, src */
	if (BPF_CLASS(mov1->code) != BPF_ALU64 ||
	    BPF_OP(mov1->code) != BPF_MOV ||
	    BPF_SRC(mov1->code) != BPF_X)
		return false;
	if (mov1->off != 0 || mov1->imm != 0)
		return false;

	/* [1] rsh64 tmp, (W-N) */
	if (BPF_CLASS(rsh_insn->code) != BPF_ALU64 ||
	    BPF_OP(rsh_insn->code) != BPF_RSH ||
	    BPF_SRC(rsh_insn->code) != BPF_K)
		return false;
	if (rsh_insn->off != 0)
		return false;
	if (rsh_insn->dst_reg != mov1->dst_reg)
		return false;
	rsh_amount = (u32)rsh_insn->imm;
	if (rsh_amount == 0 || rsh_amount >= 64)
		return false;

	/* [2] mov64 dst, src — must have the same source as [0] */
	if (BPF_CLASS(mov2->code) != BPF_ALU64 ||
	    BPF_OP(mov2->code) != BPF_MOV ||
	    BPF_SRC(mov2->code) != BPF_X)
		return false;
	if (mov2->off != 0 || mov2->imm != 0)
		return false;
	if (mov2->src_reg != mov1->src_reg)
		return false;
	if (mov1->dst_reg == mov1->src_reg || mov1->dst_reg == mov2->dst_reg)
		return false;

	/* [3] lsh64 dst, N */
	if (BPF_CLASS(lsh_insn->code) != BPF_ALU64 ||
	    BPF_OP(lsh_insn->code) != BPF_LSH ||
	    BPF_SRC(lsh_insn->code) != BPF_K)
		return false;
	if (lsh_insn->off != 0)
		return false;
	if (lsh_insn->dst_reg != mov2->dst_reg)
		return false;
	rot_amount = (u32)lsh_insn->imm;
	if (rot_amount == 0 || rot_amount >= 64)
		return false;

	/* Verify: N + rsh_amount == 64 */
	if (rot_amount + rsh_amount != 64)
		return false;

	/* [4] or64 dst, tmp */
	if (BPF_CLASS(or_insn->code) != BPF_ALU64 ||
	    BPF_OP(or_insn->code) != BPF_OR ||
	    BPF_SRC(or_insn->code) != BPF_X)
		return false;
	if (or_insn->off != 0 || or_insn->imm != 0)
		return false;
	if (or_insn->dst_reg != mov2->dst_reg)
		return false;
	if (or_insn->src_reg != mov1->dst_reg)
		return false;

	return true;
}

/**
 * bpf_jit_validate_rotate_5insn_masked - validate a 5-insn masked 32-bit rotate
 *
 * clang sometimes emits a 5-insn variant when the second MOV is eliminated:
 *   [0] mov64  tmp, src       (copy for mask+rsh path)
 *   [1] and64  tmp, mask      (AND_K or AND_X)
 *   [2,3] rsh64 tmp, (32-N) + lsh64 src, N  (either order)
 *   [4] or64   src, tmp       (combine back into src)
 *
 * This is always a 32-bit rotate (N + rsh_amount == 32).
 */
static bool bpf_jit_validate_rotate_5insn_masked(const struct bpf_insn *insns,
						   u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *mov_insn, *and_insn, *insn2, *insn3, *or_insn;
	const struct bpf_insn *lsh_insn, *rsh_insn;
	u32 rot_amount, rsh_amount;

	if (idx + 5 > insn_cnt)
		return false;

	mov_insn = &insns[idx];
	and_insn = &insns[idx + 1];
	insn2    = &insns[idx + 2];
	insn3    = &insns[idx + 3];
	or_insn  = &insns[idx + 4];

	/* [0] mov64 tmp, src */
	if (BPF_CLASS(mov_insn->code) != BPF_ALU64 ||
	    BPF_OP(mov_insn->code) != BPF_MOV ||
	    BPF_SRC(mov_insn->code) != BPF_X)
		return false;
	if (mov_insn->off != 0 || mov_insn->imm != 0)
		return false;
	if (mov_insn->dst_reg == mov_insn->src_reg)
		return false;

	/* [1] and64 tmp, mask (AND_K or AND_X) */
	if (BPF_CLASS(and_insn->code) != BPF_ALU64 ||
	    BPF_OP(and_insn->code) != BPF_AND)
		return false;
	if (BPF_SRC(and_insn->code) != BPF_K &&
	    BPF_SRC(and_insn->code) != BPF_X)
		return false;
	if (and_insn->off != 0)
		return false;
	if (and_insn->dst_reg != mov_insn->dst_reg)
		return false;

	/* [2,3] rsh and lsh in either order */
	if (BPF_OP(insn2->code) == BPF_RSH &&
	    BPF_SRC(insn2->code) == BPF_K &&
	    BPF_CLASS(insn2->code) == BPF_ALU64 &&
	    BPF_OP(insn3->code) == BPF_LSH &&
	    BPF_SRC(insn3->code) == BPF_K &&
	    BPF_CLASS(insn3->code) == BPF_ALU64) {
		rsh_insn = insn2;
		lsh_insn = insn3;
	} else if (BPF_OP(insn2->code) == BPF_LSH &&
		   BPF_SRC(insn2->code) == BPF_K &&
		   BPF_CLASS(insn2->code) == BPF_ALU64 &&
		   BPF_OP(insn3->code) == BPF_RSH &&
		   BPF_SRC(insn3->code) == BPF_K &&
		   BPF_CLASS(insn3->code) == BPF_ALU64) {
		lsh_insn = insn2;
		rsh_insn = insn3;
	} else {
		return false;
	}

	/* rsh must operate on tmp */
	if (rsh_insn->off != 0)
		return false;
	if (rsh_insn->dst_reg != mov_insn->dst_reg)
		return false;
	/* lsh must operate on original (src) */
	if (lsh_insn->off != 0)
		return false;
	if (lsh_insn->dst_reg != mov_insn->src_reg)
		return false;

	rot_amount = (u32)lsh_insn->imm;
	rsh_amount = (u32)rsh_insn->imm;
	if (rot_amount == 0 || rot_amount >= 32)
		return false;
	if (rsh_amount == 0 || rsh_amount >= 32)
		return false;
	if (rot_amount + rsh_amount != 32)
		return false;

	/* [4] or64 src, tmp */
	if (BPF_CLASS(or_insn->code) != BPF_ALU64 ||
	    BPF_OP(or_insn->code) != BPF_OR ||
	    BPF_SRC(or_insn->code) != BPF_X)
		return false;
	if (or_insn->off != 0 || or_insn->imm != 0)
		return false;
	if (or_insn->dst_reg != mov_insn->src_reg)
		return false;
	if (or_insn->src_reg != mov_insn->dst_reg)
		return false;

	/* Mask validation: for AND_K, reject zero; for AND_X, trust shape */
	if (BPF_SRC(and_insn->code) == BPF_K && and_insn->imm == 0)
		return false;

	return true;
}

/**
 * bpf_jit_validate_rotate_6insn - validate a 6-insn masked 32-bit rotate
 *
 * clang generates this pattern for 32-bit rotates in a 64-bit context:
 *   [0] mov64  tmp, src       (copy for right-shift path)
 *   [1] and64  tmp, mask      (BPF_ALU64|BPF_AND|BPF_K — mask bits)
 *   [2] rsh64  tmp, (32-N)    (right shift by complement)
 *   [3] mov64  dst, src       (copy for left-shift path, same src as [0])
 *   [4] lsh64  dst, N         (left shift)
 *   [5] or64   dst, tmp       (combine)
 *
 * This is always a 32-bit rotate (width=32), proven by the masking.
 * N + rsh_amount == 32.
 */
static bool bpf_jit_validate_rotate_6insn(const struct bpf_insn *insns,
					   u32 insn_cnt, u32 idx)
{
	const struct bpf_insn *mov1, *and_insn, *rsh_insn;
	const struct bpf_insn *mov2, *lsh_insn, *or_insn;
	u32 rot_amount, rsh_amount;

	if (idx + 6 > insn_cnt)
		return false;

	mov1     = &insns[idx];
	and_insn = &insns[idx + 1];
	rsh_insn = &insns[idx + 2];
	mov2     = &insns[idx + 3];
	lsh_insn = &insns[idx + 4];
	or_insn  = &insns[idx + 5];

	/* [0] mov64 tmp, src — reg-to-reg copy, ALU64 */
	if (BPF_CLASS(mov1->code) != BPF_ALU64 ||
	    BPF_OP(mov1->code) != BPF_MOV ||
	    BPF_SRC(mov1->code) != BPF_X)
		return false;
	if (mov1->off != 0 || mov1->imm != 0)
		return false;

	/* [1] and64 tmp, mask — immediate (AND_K) or register (AND_X) AND on tmp.
	 * clang generates AND_X when the mask constant doesn't fit in a
	 * sign-extended 32-bit immediate (e.g., 0xf0000000 for 32-bit rotate).
	 */
	if (BPF_CLASS(and_insn->code) != BPF_ALU64 ||
	    BPF_OP(and_insn->code) != BPF_AND)
		return false;
	if (BPF_SRC(and_insn->code) != BPF_K &&
	    BPF_SRC(and_insn->code) != BPF_X)
		return false;
	if (and_insn->off != 0)
		return false;
	if (and_insn->dst_reg != mov1->dst_reg)
		return false;

	/* [2] rsh64 tmp, (32-N) */
	if (BPF_CLASS(rsh_insn->code) != BPF_ALU64 ||
	    BPF_OP(rsh_insn->code) != BPF_RSH ||
	    BPF_SRC(rsh_insn->code) != BPF_K)
		return false;
	if (rsh_insn->off != 0)
		return false;
	if (rsh_insn->dst_reg != mov1->dst_reg)
		return false;
	rsh_amount = (u32)rsh_insn->imm;
	if (rsh_amount == 0 || rsh_amount >= 32)
		return false;

	/* [3] mov64 dst, src — must use the same source as [0] */
	if (BPF_CLASS(mov2->code) != BPF_ALU64 ||
	    BPF_OP(mov2->code) != BPF_MOV ||
	    BPF_SRC(mov2->code) != BPF_X)
		return false;
	if (mov2->off != 0 || mov2->imm != 0)
		return false;
	if (mov2->src_reg != mov1->src_reg)
		return false;
	if (mov1->dst_reg == mov1->src_reg || mov1->dst_reg == mov2->dst_reg)
		return false;

	/* [4] lsh64 dst, N */
	if (BPF_CLASS(lsh_insn->code) != BPF_ALU64 ||
	    BPF_OP(lsh_insn->code) != BPF_LSH ||
	    BPF_SRC(lsh_insn->code) != BPF_K)
		return false;
	if (lsh_insn->off != 0)
		return false;
	if (lsh_insn->dst_reg != mov2->dst_reg)
		return false;
	rot_amount = (u32)lsh_insn->imm;
	if (rot_amount == 0 || rot_amount >= 32)
		return false;

	/* Verify: N + rsh_amount == 32 */
	if (rot_amount + rsh_amount != 32)
		return false;

	/* [5] or64 dst, tmp */
	if (BPF_CLASS(or_insn->code) != BPF_ALU64 ||
	    BPF_OP(or_insn->code) != BPF_OR ||
	    BPF_SRC(or_insn->code) != BPF_X)
		return false;
	if (or_insn->off != 0 || or_insn->imm != 0)
		return false;
	if (or_insn->dst_reg != mov2->dst_reg)
		return false;
	if (or_insn->src_reg != mov1->dst_reg)
		return false;

	/*
	 * Validate the AND mask: for a 32-bit left-rotate by N,
	 * the right-shift path extracts bits [N..31] and shifts them
	 * right by (32-N).  The mask should preserve at most the low 32
	 * bits relevant to the rotation.
	 *
	 * For AND_K: accept any non-zero immediate mask.
	 * For AND_X: the mask is in a register (clang loads large masks
	 * via lddw into a register); we trust the pattern shape and
	 * skip the imm==0 check since imm is not used for AND_X.
	 */
	if (BPF_SRC(and_insn->code) == BPF_K && and_insn->imm == 0)
		return false;

	return true;
}

/**
 * bpf_jit_validate_rotate_rule - validate a ROTATE rule against prog
 *
 * Supports three patterns:
 *   site_len==4: 4-insn rotate, classic (mov+lsh+rsh+or) or commuted (mov+rsh+lsh+or)
 *   site_len==5: 5-insn two-copy 64-bit rotate (mov+rsh+mov+lsh+or)
 *   site_len==6: clang's 6-insn masked 32-bit rotate (mov+and+rsh+mov+lsh+or)
 */
static bool bpf_jit_validate_rotate_rule(const struct bpf_insn *insns,
					 u32 insn_cnt,
					 const struct bpf_jit_rule *rule)
{
	bool shape_ok;

	if (rule->site_len == 4)
		shape_ok = bpf_jit_validate_rotate_4insn(insns, insn_cnt,
							  rule->site_start);
	else if (rule->site_len == 5)
		/* Try 64-bit two-copy first, then 32-bit masked */
		shape_ok = bpf_jit_validate_rotate_5insn(insns, insn_cnt,
							  rule->site_start) ||
			   bpf_jit_validate_rotate_5insn_masked(insns, insn_cnt,
								 rule->site_start);
	else if (rule->site_len == 6)
		shape_ok = bpf_jit_validate_rotate_6insn(insns, insn_cnt,
							  rule->site_start);
	else
		return false;

	if (!shape_ok)
		return false;

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
		return false;

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
	u32 insn_cnt,
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
		if (idx + 3 > insn_cnt)
			return false;
		mov_insn = &insns[idx];
		first = &insns[idx + 1];
		second = &insns[idx + 2];
	} else if (rule->site_len == 2) {
		if (idx + 2 > insn_cnt)
			return false;
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

static bool bpf_jit_validate_bitfield_extract_rule(
	const struct bpf_insn *insns,
	u32 insn_cnt,
	const struct bpf_jit_rule *rule)
{
	if (!bpf_jit_parse_bitfield_extract_site(insns, insn_cnt, rule, NULL))
		return false;

	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start,
				      rule->site_len))
		return false;

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
static bool bpf_jit_validate_addr_calc_rule(const struct bpf_insn *insns,
					    u32 insn_cnt,
					    const struct bpf_jit_rule *rule)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *mov_insn, *lsh_insn, *add_insn;

	if (rule->site_len != 3)
		return false;

	if (idx + 3 > insn_cnt)
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
	if (add_insn->dst_reg != mov_insn->dst_reg)
		return false;

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
		return false;

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

	if (!bpf_jit_compute_site_end(site_start, site_len, &site_end))
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

/* CPU feature gating */
#if defined(CONFIG_X86_64)
static bool bpf_jit_check_cpu_features(u32 required)
{
	u32 available = 0;

	if (boot_cpu_has(X86_FEATURE_CMOV))
		available |= BPF_JIT_X86_CMOV;
	if (boot_cpu_has(X86_FEATURE_BMI2))
		available |= BPF_JIT_X86_BMI2;

	return (required & available) == required;
}
#else
static bool bpf_jit_check_cpu_features(u32 required)
{
	return required == 0;
}
#endif

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

static bool bpf_jit_bind_pattern_var(struct bpf_jit_var *vars, u8 var_id,
				      u8 type, s64 value)
{
	struct bpf_jit_var *var;

	if (!var_id)
		return true;
	if (var_id > BPF_JIT_MAX_PATTERN_VARS)
		return false;

	var = &vars[var_id];
	if (!var->bound) {
		var->bound = true;
		var->type = type;
		var->value = value;
		return true;
	}

	return var->type == type && var->value == value;
}

static bool bpf_jit_match_pattern(const struct bpf_insn *insns, u32 insn_cnt,
				   const struct bpf_jit_rule *rule,
				   struct bpf_jit_var *vars)
{
	u32 i;

	if (!rule->pattern || !rule->pattern_count ||
	    rule->pattern_count != rule->site_len)
		return false;
	if (!bpf_jit_site_range_valid(rule->site_start, rule->site_len,
				      insn_cnt, NULL))
		return false;

	for (i = 0; i < rule->pattern_count; i++) {
		const struct bpf_jit_pattern_insn *pattern = &rule->pattern[i];
		const struct bpf_insn *insn = &insns[rule->site_start + i];

		if (insn->code != pattern->opcode)
			return false;
		if ((pattern->flags & BPF_JIT_PATTERN_F_EXPECT_IMM) &&
		    insn->imm != pattern->expected_imm)
			return false;
		if ((pattern->flags & BPF_JIT_PATTERN_F_EXPECT_DST_REG) &&
		    insn->dst_reg != pattern->expected_dst_reg)
			return false;
		if ((pattern->flags & BPF_JIT_PATTERN_F_EXPECT_SRC_REG) &&
		    insn->src_reg != pattern->expected_src_reg)
			return false;
		if ((pattern->flags & BPF_JIT_PATTERN_F_EXPECT_OFF) &&
		    insn->off != pattern->expected_off)
			return false;
		if (!bpf_jit_bind_pattern_var(vars, pattern->dst_binding,
					      BPF_JIT_VAR_REG, insn->dst_reg) ||
		    !bpf_jit_bind_pattern_var(vars, pattern->src_binding,
					      BPF_JIT_VAR_REG, insn->src_reg) ||
		    !bpf_jit_bind_pattern_var(vars, pattern->imm_binding,
					      BPF_JIT_VAR_IMM, insn->imm) ||
		    !bpf_jit_bind_pattern_var(vars, pattern->off_binding,
					      BPF_JIT_VAR_OFF, insn->off))
			return false;
	}

	return true;
}

static bool bpf_jit_check_constraints(
	const struct bpf_jit_pattern_constraint *constraints,
	u16 constraint_count,
	const struct bpf_jit_var *vars)
{
	u16 i;

	for (i = 0; i < constraint_count; i++) {
		const struct bpf_jit_pattern_constraint *constraint = &constraints[i];
		s64 var_a, var_b;

		if (!constraint->var_a ||
		    constraint->var_a > BPF_JIT_MAX_PATTERN_VARS ||
		    !vars[constraint->var_a].bound)
			return false;

		var_a = vars[constraint->var_a].value;
		switch (constraint->type) {
		case BPF_JIT_CSTR_EQUAL:
			if (!constraint->var_b ||
			    constraint->var_b > BPF_JIT_MAX_PATTERN_VARS ||
			    !vars[constraint->var_b].bound)
				return false;
			var_b = vars[constraint->var_b].value;
			if (var_a != var_b)
				return false;
			break;
		case BPF_JIT_CSTR_SUM_CONST:
			if (!constraint->var_b ||
			    constraint->var_b > BPF_JIT_MAX_PATTERN_VARS ||
			    !vars[constraint->var_b].bound)
				return false;
			var_b = vars[constraint->var_b].value;
			if (var_a + var_b != constraint->constant)
				return false;
			break;
		case BPF_JIT_CSTR_IMM_RANGE:
			if (var_a < constraint->constant ||
			    var_a > constraint->constant_hi)
				return false;
			break;
		case BPF_JIT_CSTR_NOT_ZERO:
			if (!var_a)
				return false;
			break;
		case BPF_JIT_CSTR_MASK_BITS:
			if (!(var_a & constraint->constant))
				return false;
			break;
		case BPF_JIT_CSTR_DIFF_CONST:
			if (!constraint->var_b ||
			    constraint->var_b > BPF_JIT_MAX_PATTERN_VARS ||
			    !vars[constraint->var_b].bound)
				return false;
			var_b = vars[constraint->var_b].value;
			if (var_a - var_b != constraint->constant)
				return false;
			break;
		case BPF_JIT_CSTR_NOT_EQUAL:
			if (!constraint->var_b ||
			    constraint->var_b > BPF_JIT_MAX_PATTERN_VARS ||
			    !vars[constraint->var_b].bound)
				return false;
			var_b = vars[constraint->var_b].value;
			if (var_a == var_b)
				return false;
			break;
		default:
			return false;
		}
	}

	return true;
}

static bool bpf_jit_binding_param_valid(u16 form, u8 param)
{
	switch (form) {
	case BPF_JIT_CF_ROTATE:
		return param <= BPF_JIT_ROT_PARAM_WIDTH;
	case BPF_JIT_CF_WIDE_MEM:
		return param <= BPF_JIT_WMEM_PARAM_WIDTH;
	case BPF_JIT_CF_ADDR_CALC:
		return param <= BPF_JIT_ACALC_PARAM_SCALE;
	case BPF_JIT_CF_COND_SELECT:
		return param <= BPF_JIT_SEL_PARAM_WIDTH;
	case BPF_JIT_CF_BITFIELD_EXTRACT:
		return param <= BPF_JIT_BFX_PARAM_ORDER;
	default:
		return false;
	}
}

static bool bpf_jit_validate_binding_desc(
	const struct bpf_jit_binding *bindings,
	u16 binding_count,
	u16 canonical_form)
{
	u16 seen_params = 0;
	u16 i;

	if (binding_count > BPF_JIT_MAX_BINDINGS)
		return false;

	for (i = 0; i < binding_count; i++) {
		const struct bpf_jit_binding *binding = &bindings[i];
		u16 param_bit;

		if (binding->reserved)
			return false;
		if (!bpf_jit_binding_param_valid(canonical_form,
						 binding->canonical_param))
			return false;

		param_bit = (u16)(1U << binding->canonical_param);
		if (seen_params & param_bit)
			return false;
		seen_params |= param_bit;

		switch (binding->source_type) {
		case BPF_JIT_BIND_SOURCE_REG:
		case BPF_JIT_BIND_SOURCE_IMM:
			if (!binding->source_var ||
			    binding->source_var > BPF_JIT_MAX_PATTERN_VARS ||
			    binding->inline_const)
				return false;
			break;
		case BPF_JIT_BIND_SOURCE_CONST:
			if (binding->source_var)
				return false;
			break;
		default:
			return false;
		}
	}

	return true;
}

static bool bpf_jit_param_present(const struct bpf_jit_canonical_params *params,
				  u8 param)
{
	return param < BPF_JIT_MAX_CANONICAL_PARAMS &&
	       !!(params->present_mask & (u16)(1U << param));
}

static bool bpf_jit_param_is_reg(const struct bpf_jit_canonical_params *params,
				 u8 param)
{
	return bpf_jit_param_present(params, param) &&
	       params->params[param].type == BPF_JIT_BIND_VAL_REG;
}

static bool bpf_jit_param_is_imm(const struct bpf_jit_canonical_params *params,
				 u8 param)
{
	return bpf_jit_param_present(params, param) &&
	       params->params[param].type == BPF_JIT_BIND_VAL_IMM;
}

static bool bpf_jit_param_is_numeric(const struct bpf_jit_canonical_params *params,
				      u8 param)
{
	return bpf_jit_param_present(params, param) &&
	       (params->params[param].type == BPF_JIT_BIND_VAL_REG ||
		params->params[param].type == BPF_JIT_BIND_VAL_IMM);
}

static bool bpf_jit_extract_bindings(const struct bpf_jit_binding *bindings,
				     u16 binding_count,
				     const struct bpf_jit_var *vars,
				     struct bpf_jit_canonical_params *params)
{
	u16 i;

	memset(params, 0, sizeof(*params));

	for (i = 0; i < binding_count; i++) {
		const struct bpf_jit_binding *binding = &bindings[i];
		struct bpf_jit_binding_value *value;
		const struct bpf_jit_var *var;

		if (binding->canonical_param >= BPF_JIT_MAX_CANONICAL_PARAMS)
			return false;

		value = &params->params[binding->canonical_param];
		switch (binding->source_type) {
		case BPF_JIT_BIND_SOURCE_CONST:
			value->value = binding->inline_const;
			value->type = BPF_JIT_BIND_VAL_IMM;
			break;
		case BPF_JIT_BIND_SOURCE_REG:
		case BPF_JIT_BIND_SOURCE_IMM:
			if (!binding->source_var ||
			    binding->source_var > BPF_JIT_MAX_PATTERN_VARS)
				return false;
			var = &vars[binding->source_var];
			if (!var->bound)
				return false;
			if (binding->source_type == BPF_JIT_BIND_SOURCE_REG) {
				if (var->type != BPF_JIT_VAR_REG)
					return false;
				value->type = BPF_JIT_BIND_VAL_REG;
			} else {
				if (var->type != BPF_JIT_VAR_IMM &&
				    var->type != BPF_JIT_VAR_OFF)
					return false;
				value->type = BPF_JIT_BIND_VAL_IMM;
			}
			value->value = var->value;
			break;
		default:
			return false;
		}

		params->present_mask |= (u16)(1U << binding->canonical_param);
		if (params->param_count <= binding->canonical_param)
			params->param_count = binding->canonical_param + 1;
	}

	return true;
}

static bool bpf_jit_validate_canonical_params(
	const struct bpf_jit_rule *rule,
	const struct bpf_jit_canonical_params *params)
{
	switch (rule->canonical_form) {
	case BPF_JIT_CF_ROTATE: {
		s64 width, amount;

		if (!bpf_jit_param_is_reg(params, BPF_JIT_ROT_PARAM_DST_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_ROT_PARAM_SRC_REG) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_ROT_PARAM_AMOUNT) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_ROT_PARAM_WIDTH))
			return false;

		width = params->params[BPF_JIT_ROT_PARAM_WIDTH].value;
		amount = params->params[BPF_JIT_ROT_PARAM_AMOUNT].value;
		return (width == 32 || width == 64) &&
		       amount > 0 && amount < width;
	}
	case BPF_JIT_CF_WIDE_MEM: {
		s64 encoded_width, width, flags;

		if (!bpf_jit_param_is_reg(params, BPF_JIT_WMEM_PARAM_DST_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_WMEM_PARAM_BASE_REG) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_WMEM_PARAM_BASE_OFF) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_WMEM_PARAM_WIDTH))
			return false;

		encoded_width = params->params[BPF_JIT_WMEM_PARAM_WIDTH].value;
		width = encoded_width & BPF_JIT_WMEM_WIDTH_MASK;
		flags = encoded_width & ~BPF_JIT_WMEM_WIDTH_MASK;
		return width >= 2 && width <= 8 &&
		       (flags == 0 || flags == BPF_JIT_WMEM_F_BIG_ENDIAN);
	}
	case BPF_JIT_CF_ADDR_CALC: {
		s64 scale;

		if (!bpf_jit_param_is_reg(params, BPF_JIT_ACALC_PARAM_DST_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_ACALC_PARAM_BASE_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_ACALC_PARAM_INDEX_REG) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_ACALC_PARAM_SCALE))
			return false;

		scale = params->params[BPF_JIT_ACALC_PARAM_SCALE].value;
		return scale >= 1 && scale <= 3;
	}
	case BPF_JIT_CF_COND_SELECT: {
		s64 width, cond_op;

		if (!bpf_jit_param_is_reg(params, BPF_JIT_SEL_PARAM_DST_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_SEL_PARAM_COND_A) ||
		    !bpf_jit_param_is_numeric(params, BPF_JIT_SEL_PARAM_COND_B) ||
		    !bpf_jit_param_is_numeric(params, BPF_JIT_SEL_PARAM_TRUE_VAL) ||
		    !bpf_jit_param_is_numeric(params, BPF_JIT_SEL_PARAM_FALSE_VAL) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_SEL_PARAM_COND_OP) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_SEL_PARAM_WIDTH))
			return false;

		width = params->params[BPF_JIT_SEL_PARAM_WIDTH].value;
		cond_op = params->params[BPF_JIT_SEL_PARAM_COND_OP].value;
		return (width == 32 || width == 64) && bpf_jit_cond_op_valid(cond_op);
	}
	case BPF_JIT_CF_BITFIELD_EXTRACT: {
		s64 width, shift, order;

		if (!bpf_jit_param_is_reg(params, BPF_JIT_BFX_PARAM_DST_REG) ||
		    !bpf_jit_param_is_reg(params, BPF_JIT_BFX_PARAM_SRC_REG) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_BFX_PARAM_SHIFT) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_BFX_PARAM_MASK) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_BFX_PARAM_WIDTH) ||
		    !bpf_jit_param_is_imm(params, BPF_JIT_BFX_PARAM_ORDER))
			return false;

		width = params->params[BPF_JIT_BFX_PARAM_WIDTH].value;
		shift = params->params[BPF_JIT_BFX_PARAM_SHIFT].value;
		order = params->params[BPF_JIT_BFX_PARAM_ORDER].value;
		return (width == 32 || width == 64) &&
		       shift >= 0 && shift < width &&
		       (order == BPF_JIT_BFX_ORDER_SHIFT_MASK ||
			order == BPF_JIT_BFX_ORDER_MASK_SHIFT);
	}
	default:
		return false;
	}
}

static bool bpf_jit_validate_pattern_rule(const struct bpf_insn *insns,
					   u32 insn_cnt,
					   const struct bpf_jit_rule *rule,
					   struct bpf_jit_canonical_params *params)
{
	struct bpf_jit_var vars[BPF_JIT_MAX_PATTERN_VARS + 1] = {};
	struct bpf_jit_canonical_params tmp_params;

	if (rule->rule_kind != BPF_JIT_RK_PATTERN || !rule->pattern ||
	    !bpf_jit_pattern_rule_shape_valid(rule))
		return false;
	if (!bpf_jit_match_pattern(insns, insn_cnt, rule, vars))
		return false;
	if (rule->constraint_count &&
	    (!rule->constraints ||
	     !bpf_jit_check_constraints(rule->constraints, rule->constraint_count,
					     vars)))
		return false;
	if (!rule->bindings || !rule->binding_count ||
	    !bpf_jit_extract_bindings(rule->bindings, rule->binding_count,
					    vars, &tmp_params) ||
	    !bpf_jit_validate_canonical_params(rule, &tmp_params))
		return false;
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start,
				      rule->site_len))
		return false;
	if (params)
		*params = tmp_params;

	return true;
}

static bool bpf_jit_validate_rule(const struct bpf_insn *insns,
				  u32 insn_cnt,
				  const struct bpf_jit_rule *rule,
				  struct bpf_jit_canonical_params *params)
{
	u16 form = bpf_jit_rule_form(rule);
	u32 required_cpu_features;

	if (params)
		memset(params, 0, sizeof(*params));

	/* Bounds check */
	if (!bpf_jit_site_range_valid(rule->site_start, rule->site_len,
				      insn_cnt, NULL))
		return false;
	if (!form || !bpf_jit_native_choice_valid(form, rule->native_choice))
		return false;

	/* Check CPU features before kind-specific validation */
	required_cpu_features = rule->cpu_features_required |
		bpf_jit_cpu_features_for_native_choice(form, rule->native_choice);
	if (required_cpu_features &&
	    !bpf_jit_check_cpu_features(required_cpu_features))
		return false;

	/* Layer-2 generic check: reject sites with side effects */
	if (bpf_jit_site_has_side_effects(insns, rule->site_start, rule->site_len))
		return false;

	switch (rule->rule_kind) {
	case BPF_JIT_RK_COND_SELECT:
		return bpf_jit_validate_cond_select_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_WIDE_MEM:
		return bpf_jit_validate_wide_mem_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_ROTATE:
		return bpf_jit_validate_rotate_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_ADDR_CALC:
		return bpf_jit_validate_addr_calc_rule(insns, insn_cnt, rule);
	case BPF_JIT_RK_BITFIELD_EXTRACT:
		return bpf_jit_validate_bitfield_extract_rule(insns, insn_cnt,
							      rule);
	case BPF_JIT_RK_PATTERN:
		return bpf_jit_validate_pattern_rule(insns, insn_cnt, rule,
						     params);

	default:
		return false;
	}
}

static bool bpf_jit_rule_within_single_subprog(const struct bpf_prog *prog,
					       const struct bpf_jit_rule *rule)
{
	const struct bpf_prog_aux *main_aux;
	u32 site_end;
	u32 i;

	if (!bpf_jit_compute_site_end(rule->site_start, rule->site_len, &site_end))
		return false;

	main_aux = prog->aux->main_prog_aux ? prog->aux->main_prog_aux : prog->aux;
	if (!main_aux->func || main_aux->func_cnt <= 1)
		return true;

	for (i = 0; i < main_aux->func_cnt; i++) {
		const struct bpf_prog *func = main_aux->func[i];
		u32 subprog_start;
		u32 subprog_end;

		if (!func || !func->aux)
			continue;

		subprog_start = func->aux->subprog_start;
		if (i + 1 < main_aux->func_cnt &&
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

	policy = kvmalloc(struct_size(policy, rules, rule_cnt),
			  GFP_KERNEL_ACCOUNT);
	if (!policy)
		return ERR_PTR(-ENOMEM);

	policy->rule_cnt = rule_cnt;
	policy->active_cnt = 0;
	policy->blob = NULL;
	return policy;
}

static bool bpf_jit_validate_pattern_desc(
	const struct bpf_jit_pattern_insn *pattern,
	u16 pattern_count)
{
	u16 i;

	if (!pattern_count || pattern_count > BPF_JIT_MAX_PATTERN_LEN)
		return false;

	for (i = 0; i < pattern_count; i++) {
		const struct bpf_jit_pattern_insn *entry = &pattern[i];

		if (!bpf_opcode_in_insntable(entry->opcode))
			return false;
		if (entry->dst_binding > BPF_JIT_MAX_PATTERN_VARS ||
		    entry->src_binding > BPF_JIT_MAX_PATTERN_VARS ||
		    entry->imm_binding > BPF_JIT_MAX_PATTERN_VARS ||
		    entry->off_binding > BPF_JIT_MAX_PATTERN_VARS)
			return false;
		if (entry->flags & ~(BPF_JIT_PATTERN_F_EXPECT_IMM |
				     BPF_JIT_PATTERN_F_EXPECT_DST_REG |
				     BPF_JIT_PATTERN_F_EXPECT_SRC_REG |
				     BPF_JIT_PATTERN_F_EXPECT_OFF))
			return false;
		if (entry->expected_dst_reg > 0xf || entry->expected_src_reg > 0xf)
			return false;
	}

	return true;
}

static bool bpf_jit_validate_constraint_desc(
	const struct bpf_jit_pattern_constraint *constraints,
	u16 constraint_count)
{
	u16 i;

	if (constraint_count > BPF_JIT_MAX_CONSTRAINTS)
		return false;

	for (i = 0; i < constraint_count; i++) {
		const struct bpf_jit_pattern_constraint *constraint = &constraints[i];

		if (constraint->reserved || constraint->reserved2)
			return false;

		switch (constraint->type) {
		case BPF_JIT_CSTR_EQUAL:
		case BPF_JIT_CSTR_SUM_CONST:
		case BPF_JIT_CSTR_DIFF_CONST:
		case BPF_JIT_CSTR_NOT_EQUAL:
			if (!constraint->var_a || !constraint->var_b)
				return false;
			break;
		case BPF_JIT_CSTR_IMM_RANGE:
		case BPF_JIT_CSTR_NOT_ZERO:
		case BPF_JIT_CSTR_MASK_BITS:
			if (!constraint->var_a)
				return false;
			break;
		default:
			return false;
		}

		if (constraint->var_a > BPF_JIT_MAX_PATTERN_VARS ||
		    constraint->var_b > BPF_JIT_MAX_PATTERN_VARS)
			return false;
	}

	return true;
}

/*
 * v1 policy parser — DEPRECATED.
 * Retained for backward compatibility only. All new directives and patterns
 * MUST use the v2 (declarative pattern) path via BPF_JIT_RK_PATTERN.
 * Do NOT add new rule_kind or native_choice handling here.
 */
static struct bpf_jit_policy *
bpf_jit_parse_policy_v1(struct bpf_prog *prog,
			 const struct bpf_jit_policy_hdr *hdr,
			 size_t blob_len)
{
	const struct bpf_jit_rewrite_rule *urules;
	struct bpf_jit_policy *policy;
	size_t expected_len, rules_len;
	u32 i;

	if (check_mul_overflow((size_t)hdr->rule_cnt,
			       sizeof(struct bpf_jit_rewrite_rule),
			       &rules_len))
		return ERR_PTR(-E2BIG);

	expected_len = sizeof(*hdr) + rules_len;
	if (expected_len != blob_len)
		return ERR_PTR(-EINVAL);

	policy = bpf_jit_alloc_policy(hdr->rule_cnt);
	if (IS_ERR(policy))
		return policy;

	urules = (const struct bpf_jit_rewrite_rule *)(hdr + 1);
	for (i = 0; i < hdr->rule_cnt; i++) {
		struct bpf_jit_rule *rule = &policy->rules[i];
		bool active;

		rule->rule_kind = urules[i].rule_kind;
		rule->canonical_form = 0;
		rule->native_choice = urules[i].native_choice;
		rule->pattern_count = 0;
		rule->constraint_count = 0;
		rule->binding_count = 0;
		rule->reserved = 0;
		rule->pattern = NULL;
		rule->constraints = NULL;
		rule->bindings = NULL;
		memset(&rule->params, 0, sizeof(rule->params));
		rule->site_start = urules[i].site_start;
		rule->site_len = urules[i].site_len;
		rule->priority = urules[i].priority;
		rule->cpu_features_required = urules[i].cpu_features_required;

		active = bpf_jit_rule_within_single_subprog(prog, rule) &&
			 bpf_jit_validate_rule(prog->insnsi, prog->len, rule,
					       NULL);
		if (active) {
			rule->flags = BPF_JIT_REWRITE_F_ACTIVE;
			policy->active_cnt++;
		} else {
			rule->flags = 0;
		}
	}

	return policy;
}

static struct bpf_jit_policy *
bpf_jit_parse_policy_v2(struct bpf_prog *prog,
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
		const struct bpf_jit_pattern_insn *pattern;
		const struct bpf_jit_pattern_constraint *constraints;
		const struct bpf_jit_binding *bindings;
		struct bpf_jit_rule *rule = &policy->rules[i];
		struct bpf_jit_rule tmp_rule = {};
		size_t pattern_bytes, constraint_bytes, binding_bytes;
		size_t expected_rule_len;
		bool active;

		if ((size_t)(end - cursor) < sizeof(*urule)) {
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		urule = (const struct bpf_jit_rewrite_rule_v2 *)cursor;
		tmp_rule.rule_kind = urule->rule_kind;
		tmp_rule.canonical_form = urule->canonical_form;
		tmp_rule.site_len = urule->site_len;

		if (urule->rule_kind != BPF_JIT_RK_PATTERN ||
		    !urule->pattern_count ||
		    urule->pattern_count != urule->site_len ||
		    !bpf_jit_pattern_rule_shape_valid(&tmp_rule)) {
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		if (check_mul_overflow((size_t)urule->pattern_count,
				       sizeof(struct bpf_jit_pattern_insn),
				       &pattern_bytes) ||
		    check_mul_overflow((size_t)urule->constraint_count,
				       sizeof(struct bpf_jit_pattern_constraint),
				       &constraint_bytes) ||
		    check_mul_overflow((size_t)urule->binding_count,
				       sizeof(struct bpf_jit_binding),
				       &binding_bytes) ||
		    check_add_overflow(sizeof(*urule), pattern_bytes,
				       &expected_rule_len) ||
		    check_add_overflow(expected_rule_len, constraint_bytes,
				       &expected_rule_len) ||
		    check_add_overflow(expected_rule_len, binding_bytes,
				       &expected_rule_len) ||
		    urule->rule_len != expected_rule_len ||
		    (size_t)(end - cursor) < urule->rule_len) {
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		pattern = (const struct bpf_jit_pattern_insn *)(urule + 1);
		constraints = (const struct bpf_jit_pattern_constraint *)
			((const u8 *)pattern + pattern_bytes);
		bindings = (const struct bpf_jit_binding *)
			((const u8 *)constraints + constraint_bytes);

		if (!bpf_jit_validate_pattern_desc(pattern, urule->pattern_count) ||
		    !bpf_jit_validate_constraint_desc(constraints,
						    urule->constraint_count) ||
		    !bpf_jit_validate_binding_desc(bindings, urule->binding_count,
						  urule->canonical_form)) {
			bpf_jit_free_policy(policy);
			return ERR_PTR(-EINVAL);
		}

		rule->rule_kind = urule->rule_kind;
		rule->canonical_form = urule->canonical_form;
		rule->native_choice = urule->native_choice;
		rule->pattern_count = urule->pattern_count;
		rule->constraint_count = urule->constraint_count;
		rule->binding_count = urule->binding_count;
		rule->reserved = urule->reserved;
		rule->pattern = pattern;
		rule->constraints = constraints;
		rule->bindings = bindings;
		memset(&rule->params, 0, sizeof(rule->params));
		rule->site_start = urule->site_start;
		rule->site_len = urule->site_len;
		rule->priority = urule->priority;
		rule->cpu_features_required = urule->cpu_features_required;

		active = bpf_jit_rule_within_single_subprog(prog, rule) &&
			 bpf_jit_validate_rule(prog->insnsi, prog->len, rule,
					       &rule->params);
		if (active) {
			rule->flags = BPF_JIT_REWRITE_F_ACTIVE;
			policy->active_cnt++;
		} else {
			rule->flags = 0;
		}

		cursor += urule->rule_len;
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
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (hdr->total_len != blob_len) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (hdr->rule_cnt > BPF_JIT_MAX_RULES) {
		policy = ERR_PTR(-E2BIG);
		goto out;
	}

	/* Digest binding: insn_cnt must match */
	if (hdr->insn_cnt != prog->len) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	/* Validate prog_tag binding */
	if (memcmp(hdr->prog_tag, prog->tag, sizeof(prog->tag)) != 0) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	/* Validate architecture */
#if defined(CONFIG_X86_64)
	if (hdr->arch_id != BPF_JIT_ARCH_X86_64) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}
#else
	policy = ERR_PTR(-EOPNOTSUPP);
	goto out;
#endif

	if (!hdr->rule_cnt) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	switch (hdr->version) {
	case BPF_JIT_POLICY_VERSION_1:
		policy = bpf_jit_parse_policy_v1(prog, hdr, blob_len);
		break;
	case BPF_JIT_POLICY_VERSION_2:
		policy = bpf_jit_parse_policy_v2(prog, hdr, blob, blob_len);
		if (!IS_ERR(policy))
			blob = NULL;
		break;
	default:
		policy = ERR_PTR(-EINVAL);
		break;
	}
	if (IS_ERR(policy))
		goto out;

	/* Sort by site_start for efficient lookup */
	sort(policy->rules, policy->rule_cnt,
	     sizeof(struct bpf_jit_rule), rule_cmp, NULL);

	pr_debug("bpf_jit_recompile: prog insn_cnt=%u rule_cnt=%u active=%u\n",
		 prog->len, policy->rule_cnt, policy->active_cnt);

	for (i = 0; i < policy->rule_cnt; i++) {
		struct bpf_jit_rule *rule = &policy->rules[i];

		pr_debug("bpf_jit_recompile: rule[%u] kind=%u site=%u+%u choice=%u cpu_feat=0x%x -> %s\n",
			 i, rule->rule_kind, rule->site_start, rule->site_len,
			 rule->native_choice, rule->cpu_features_required,
			 (rule->flags & BPF_JIT_REWRITE_F_ACTIVE) ? "active" : "rejected");
	}

out:
	kvfree(blob);
	return policy;
}

/**
 * bpf_jit_rule_lookup - find a rule covering the given BPF insn index
 *
 * Binary search on sorted rules array.
 * Returns the highest-priority active rule at this site, or NULL.
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
		u32 site_end;

		if (!bpf_jit_compute_site_end(rule->site_start, rule->site_len, &site_end))
			return NULL;

		if (insn_idx < rule->site_start) {
			hi = mid;
		} else if (insn_idx >= site_end) {
			lo = mid + 1;
		} else {
			/* Found a rule covering insn_idx.
			 * Since sorted by (site_start, -priority), the first
			 * active match at this site_start is the best.
			 * But we need the rule whose site_start matches.
			 */
			if (insn_idx != rule->site_start)
				return NULL;
			if (rule->flags & BPF_JIT_REWRITE_F_ACTIVE)
				return rule;
			return NULL;
		}
	}

	return NULL;
}

/**
 * bpf_prog_jit_recompile - BPF_PROG_JIT_RECOMPILE syscall handler
 *
 * Takes a prog_fd for an already-loaded program and a policy_fd
 * for a sealed memfd containing a v4 policy blob.
 * Parses the policy, validates rules, stores the policy on the prog,
 * and triggers a re-JIT.
 */
static int bpf_jit_recompile_prog_images(struct bpf_prog *prog)
{
	struct bpf_prog_aux *main_aux;

	main_aux = prog->aux->main_prog_aux ? prog->aux->main_prog_aux : prog->aux;
	if (main_aux->func_cnt && main_aux->func) {
		u32 i;

		for (i = 0; i < main_aux->func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];

			if (!func || bpf_int_jit_compile(func) != func)
				return -ENOMEM;
		}

		for (i = 0; i < main_aux->func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];
			struct bpf_insn *insn;
			u32 j;

			if (!func)
				return -EINVAL;

			insn = func->insnsi;
			for (j = 0; j < func->len; j++, insn++) {
				int subprog;

				if (bpf_pseudo_func(insn)) {
					subprog = insn->off;
					insn[0].imm = (u32)(long)main_aux->func[subprog]->bpf_func;
					insn[1].imm = ((u64)(long)main_aux->func[subprog]->bpf_func) >> 32;
					continue;
				}
				if (!bpf_pseudo_call_insn(insn))
					continue;

				subprog = insn->off;
				insn->imm = BPF_CALL_IMM(main_aux->func[subprog]->bpf_func);
			}
		}

		for (i = 0; i < main_aux->func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];
			void *old_bpf_func = func ? func->bpf_func : NULL;
			struct bpf_prog *recompiled;

			if (!func)
				return -EINVAL;

			recompiled = bpf_int_jit_compile(func);
			if (!recompiled)
				return -ENOMEM;
			if (recompiled != func)
				return -EINVAL;
			if (i > 0 && func->bpf_func != old_bpf_func)
				return -EINVAL;
		}

		prog->bpf_func = main_aux->func[0]->bpf_func;
		prog->jited_len = main_aux->func[0]->jited_len;
		prog->aux->extable = main_aux->func[0]->aux->extable;
		prog->aux->num_exentries = main_aux->func[0]->aux->num_exentries;
		prog->aux->exception_boundary = main_aux->func[0]->aux->exception_boundary;
		return 0;
	}

	if (!bpf_int_jit_compile(prog))
		return -ENOMEM;

	return 0;
}

int bpf_prog_jit_recompile(union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct bpf_jit_policy *policy;
	struct bpf_jit_policy *old_policy;
	int err = 0;

	if (attr->jit_recompile.flags)
		return -EINVAL;

	if (!capable(CAP_BPF) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	prog = bpf_prog_get(attr->jit_recompile.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	/* Must be a JITed program */
	if (!prog->jited) {
		err = -EINVAL;
		goto out_put;
	}

	/* Stock re-JIT (clear policy) */
	if (attr->jit_recompile.policy_fd == 0) {
		old_policy = prog->aux->jit_policy;
		prog->aux->jit_policy = NULL;
		if (old_policy)
			bpf_jit_free_policy(old_policy);

		err = bpf_jit_recompile_prog_images(prog);
		goto out_put;
	}

	/* Don't support blinded programs in POC */
	if (prog->blinded) {
		err = -EOPNOTSUPP;
		goto out_put;
	}

	/* Parse and validate policy blob */
	policy = bpf_jit_parse_policy(prog, attr->jit_recompile.policy_fd);
	if (IS_ERR(policy)) {
		err = PTR_ERR(policy);
		goto out_put;
	}

	if (policy->active_cnt == 0) {
		bpf_jit_free_policy(policy);
		err = -EINVAL;
		goto out_put;
	}

	/* Swap policy on prog */
	old_policy = prog->aux->jit_policy;
	prog->aux->jit_policy = policy;
	if (old_policy)
		bpf_jit_free_policy(old_policy);

	/* Trigger re-JIT for the active func[] images. */
	err = bpf_jit_recompile_prog_images(prog);
	if (err) {
		/* Clean up the policy we just stored */
		bpf_jit_free_policy(prog->aux->jit_policy);
		prog->aux->jit_policy = NULL;
		goto out_put;
	}

	out_put:
	bpf_prog_put(prog);
	return err;
}
