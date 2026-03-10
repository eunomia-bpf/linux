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
	u32 site_end = site_start + site_len;
	u32 i;

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

/**
 * bpf_jit_validate_wide_mem_rule - validate a WIDE_MEM rule against prog
 *
 * Check that the BPF insn sequence at site_start is a byte-load ladder:
 * consecutive BPF_LDX_MEM(BPF_B, ...) from the same base register at
 * contiguous offsets, followed by shifts and ORs to reconstruct a wider value.
 *
 * For the POC, we validate a simple pattern:
 *   ldxb dst, [base+off]
 *   ldxb tmp, [base+off+1]
 *   lsh  tmp, 8
 *   or   dst, tmp
 *   ... (repeated for each additional byte)
 *
 * The rule specifies site_len to cover all these instructions.
 */
static bool bpf_jit_validate_wide_mem_rule(const struct bpf_insn *insns,
					   u32 insn_cnt,
					   const struct bpf_jit_rule *rule)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *first;
	u8 base_reg;
	s16 base_off;

	if (idx + rule->site_len > insn_cnt)
		return false;

	/* Must have at least 2 insns (one byte load + something) */
	if (rule->site_len < 4)
		return false;

	first = &insns[idx];

	/* First insn must be BPF_LDX | BPF_MEM | BPF_B */
	if (first->code != (BPF_LDX | BPF_MEM | BPF_B))
		return false;

	base_reg = first->src_reg;
	base_off = first->off;

	/*
	 * Validate pattern: for a 2-byte wide load, expect:
	 *   [0] ldxb dst, [base+off]
	 *   [1] ldxb tmp, [base+off+1]
	 *   [2] lsh64 tmp, 8
	 *   [3] or64  dst, tmp
	 *
	 * For a 4-byte wide load, expect 3 more groups of (ldxb, lsh, or)
	 * after the first ldxb.
	 *
	 * General pattern: 1 + (width-1)*3 instructions, where width = site_len/3+1
	 * would give us the total width. But let's just check the minimum structure.
	 */

	/* Check that expected byte count matches site_len:
	 * For N bytes: 1 (first load) + (N-1)*3 (load+shift+or) = 3N-2 insns
	 * So N = (site_len + 2) / 3
	 */
	{
		u32 expected_bytes;
		u32 i;

		if ((rule->site_len + 2) % 3 != 0)
			return false;

		expected_bytes = (rule->site_len + 2) / 3;
		if (expected_bytes < 2 || expected_bytes > 8)
			return false;

		/* Only support power-of-2 widths that the emitter handles */
		if (expected_bytes != 2 && expected_bytes != 4 && expected_bytes != 8)
			return false;

		/* Validate each subsequent byte group */
		for (i = 1; i < expected_bytes; i++) {
			u32 group_base = idx + 1 + (i - 1) * 3;
			const struct bpf_insn *load_insn = &insns[group_base];
			const struct bpf_insn *shift_insn = &insns[group_base + 1];
			const struct bpf_insn *or_insn = &insns[group_base + 2];

			/* Check ldxb */
			if (load_insn->code != (BPF_LDX | BPF_MEM | BPF_B))
				return false;
			if (load_insn->src_reg != base_reg)
				return false;
			if (load_insn->off != base_off + (s16)i)
				return false;

			/* Check lsh64 imm (shift by i*8) */
			if (shift_insn->code != (BPF_ALU64 | BPF_LSH | BPF_K))
				return false;
			if (shift_insn->imm != (s32)(i * 8))
				return false;
			if (shift_insn->dst_reg != load_insn->dst_reg)
				return false;

			/* Check or64 */
			if (or_insn->code != (BPF_ALU64 | BPF_OR | BPF_X))
				return false;
			if (or_insn->dst_reg != first->dst_reg)
				return false;
			if (or_insn->src_reg != load_insn->dst_reg)
				return false;
		}
	}

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
		return false;

	return true;
}

/**
 * bpf_jit_validate_rotate_rule - validate a ROTATE rule against prog
 *
 * Check that the BPF insn sequence at site_start matches a rotate idiom:
 *   [0] mov   tmp, dst        (copy original)
 *   [1] lsh64 dst, N          (left shift by rotation amount)
 *   [2] rsh64 tmp, (W-N)      (right shift complement)
 *   [3] or64  dst, tmp        (combine)
 *
 * Where W is 32 or 64 and N is the rotation amount (1..W-1).
 * site_len must be 4.
 */
static bool bpf_jit_validate_rotate_rule(const struct bpf_insn *insns,
					 u32 insn_cnt,
					 const struct bpf_jit_rule *rule)
{
	u32 idx = rule->site_start;
	const struct bpf_insn *mov_insn, *lsh_insn, *rsh_insn, *or_insn;
	u8 lsh_cls, rsh_cls, or_cls;
	u32 width, rot_amount;

	if (rule->site_len != 4)
		return false;

	if (idx + 4 > insn_cnt)
		return false;

	mov_insn = &insns[idx];
	lsh_insn = &insns[idx + 1];
	rsh_insn = &insns[idx + 2];
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

	/* tmp = mov_insn->dst_reg, src (original) = mov_insn->src_reg */
	/* [1] lsh dst, N — dst must be the original src, imm is rotation amount */
	lsh_cls = BPF_CLASS(lsh_insn->code);
	if (BPF_OP(lsh_insn->code) != BPF_LSH || BPF_SRC(lsh_insn->code) != BPF_K)
		return false;
	if ((width == 64 && lsh_cls != BPF_ALU64) ||
	    (width == 32 && lsh_cls != BPF_ALU))
		return false;
	if (lsh_insn->dst_reg != mov_insn->src_reg)
		return false;

	rot_amount = (u32)lsh_insn->imm;
	if (rot_amount == 0 || rot_amount >= width)
		return false;

	/* [2] rsh tmp, (W - N) */
	rsh_cls = BPF_CLASS(rsh_insn->code);
	if (BPF_OP(rsh_insn->code) != BPF_RSH || BPF_SRC(rsh_insn->code) != BPF_K)
		return false;
	if ((width == 64 && rsh_cls != BPF_ALU64) ||
	    (width == 32 && rsh_cls != BPF_ALU))
		return false;
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
	if (or_insn->dst_reg != mov_insn->src_reg)
		return false;
	if (or_insn->src_reg != mov_insn->dst_reg)
		return false;

	/* Reject if any external jump targets the interior of this pattern */
	if (bpf_jit_has_interior_edge(insns, insn_cnt, rule->site_start, rule->site_len))
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
	u32 i;

	for (i = site_start; i < site_start + site_len; i++) {
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

static bool bpf_jit_validate_rule(const struct bpf_insn *insns,
				  u32 insn_cnt,
				  const struct bpf_jit_rule *rule)
{
	/* Bounds check */
	if (rule->site_start + rule->site_len > insn_cnt)
		return false;

	/* Check CPU features before kind-specific validation */
	if (rule->cpu_features_required) {
		if (!bpf_jit_check_cpu_features(rule->cpu_features_required))
			return false;
	}

	/* Layer-2 generic check: reject sites with side effects */
	if (bpf_jit_site_has_side_effects(insns, rule->site_start, rule->site_len))
		return false;

	switch (rule->rule_kind) {
	case BPF_JIT_RK_COND_SELECT:
		/* Validate native_choice */
		if (rule->native_choice != BPF_JIT_SEL_CMOVCC &&
		    rule->native_choice != BPF_JIT_SEL_BRANCH)
			return false;
		return bpf_jit_validate_cond_select_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_WIDE_MEM:
		if (rule->native_choice != BPF_JIT_WMEM_WIDE_LOAD &&
		    rule->native_choice != BPF_JIT_WMEM_BYTE_LOADS)
			return false;
		return bpf_jit_validate_wide_mem_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_ROTATE:
		if (rule->native_choice != BPF_JIT_ROT_ROR &&
		    rule->native_choice != BPF_JIT_ROT_RORX &&
		    rule->native_choice != BPF_JIT_ROT_SHIFT)
			return false;
		return bpf_jit_validate_rotate_rule(insns, insn_cnt, rule);

	case BPF_JIT_RK_ADDR_CALC:
		if (rule->native_choice != BPF_JIT_ACALC_LEA &&
		    rule->native_choice != BPF_JIT_ACALC_SHIFT_ADD)
			return false;
		return bpf_jit_validate_addr_calc_rule(insns, insn_cnt, rule);

	default:
		return false;
	}
}

static u32 bpf_jit_main_subprog_end(const struct bpf_prog *prog)
{
	if (prog->aux->func_cnt > 1 && prog->aux->func &&
	    prog->aux->func[1] && prog->aux->func[1]->aux)
		return prog->aux->func[1]->aux->subprog_start;

	return prog->len;
}

/**
 * bpf_jit_parse_policy - parse and validate a v4 policy blob from a sealed memfd
 * @prog: the already-verified BPF program
 * @fd:   sealed memfd containing the policy blob
 *
 * Returns a validated bpf_jit_policy, or ERR_PTR on error.
 */
struct bpf_jit_policy *bpf_jit_parse_policy(struct bpf_prog *prog, int fd)
{
	const struct bpf_jit_policy_hdr *hdr;
	const struct bpf_jit_rewrite_rule *urules;
	struct bpf_jit_policy *policy = NULL;
	struct fd f = fdget(fd);
	size_t blob_len, expected_len, rules_len;
	void *blob = NULL;
	loff_t pos = 0;
	ssize_t nread;
	u32 i;
	u32 main_subprog_end;

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
	    hdr->version != BPF_JIT_POLICY_VERSION ||
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

	if (check_mul_overflow((size_t)hdr->rule_cnt,
			       sizeof(struct bpf_jit_rewrite_rule),
			       &rules_len)) {
		policy = ERR_PTR(-E2BIG);
		goto out;
	}

	expected_len = sizeof(*hdr) + rules_len;
	if (expected_len != blob_len) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	if (!hdr->rule_cnt) {
		policy = ERR_PTR(-EINVAL);
		goto out;
	}

	urules = (const struct bpf_jit_rewrite_rule *)(hdr + 1);
	main_subprog_end = bpf_jit_main_subprog_end(prog);

	/* Allocate policy */
	policy = kvmalloc(struct_size(policy, rules, hdr->rule_cnt), GFP_KERNEL_ACCOUNT);
	if (!policy) {
		policy = ERR_PTR(-ENOMEM);
		goto out;
	}

	policy->rule_cnt = hdr->rule_cnt;
	policy->active_cnt = 0;

	/* Copy rules and validate each one */
	for (i = 0; i < hdr->rule_cnt; i++) {
		struct bpf_jit_rule *rule = &policy->rules[i];
		bool active;

		rule->rule_kind = urules[i].rule_kind;
		rule->native_choice = urules[i].native_choice;
		rule->site_start = urules[i].site_start;
		rule->site_len = urules[i].site_len;
		rule->priority = urules[i].priority;
		rule->reserved = 0;
		rule->cpu_features_required = urules[i].cpu_features_required;

		/*
		 * BPF_PROG_JIT_RECOMPILE currently recompiles the main prog
		 * image only. Rules in non-main subprogs are therefore
		 * rejected until subprog-aware re-JIT support exists.
		 */
		active = rule->site_start + rule->site_len <= main_subprog_end &&
			 bpf_jit_validate_rule(prog->insnsi, prog->len, rule);
		if (active) {
			rule->flags = BPF_JIT_REWRITE_F_ACTIVE;
			policy->active_cnt++;
		} else {
			rule->flags = 0; /* failed validation, will be skipped */
		}
	}

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

		if (insn_idx < rule->site_start) {
			hi = mid;
		} else if (insn_idx >= rule->site_start + rule->site_len) {
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

		/* Trigger stock re-JIT by calling bpf_int_jit_compile again.
		 * Save prog pointer: bpf_int_jit_compile returns prog on
		 * success or NULL on OOM, but prog itself is not freed.
		 */
		{
			struct bpf_prog *recompiled = bpf_int_jit_compile(prog);
			if (!recompiled)
				err = -ENOMEM;
		}
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

	/* Trigger re-JIT.
	 * Save prog pointer: bpf_int_jit_compile returns prog on success
	 * or NULL on OOM, but prog itself is not freed.  On failure we
	 * must clean up the policy we just stored.
	 */
	{
		struct bpf_prog *recompiled = bpf_int_jit_compile(prog);
		if (!recompiled) {
			/* Clean up the policy we just stored */
			bpf_jit_free_policy(prog->aux->jit_policy);
			prog->aux->jit_policy = NULL;
			err = -ENOMEM;
			goto out_put;
		}
	}

out_put:
	bpf_prog_put(prog);
	return err;
}
