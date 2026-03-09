// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/bpf_verifier.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <uapi/linux/fcntl.h>

#define BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE SZ_64K

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
