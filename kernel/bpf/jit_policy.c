// SPDX-License-Identifier: GPL-2.0-only
/* BPF JIT policy parsing and lookup */
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <uapi/linux/fcntl.h>

#define BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE SZ_512K
#define BPF_JIT_MAX_RULES		1024

static bool bpf_jit_directives_valid_memfd(struct file *file)
{
	int seals;

	seals = memfd_fcntl(file, F_GET_SEALS, 0);
	if (seals < 0)
		return false;

	return (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) ==
	       (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK);
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
#elif defined(CONFIG_ARM64)
	if (hdr->arch_id != BPF_JIT_ARCH_ARM64) {
		bpf_jit_recompile_prog_log(
			prog,
			"policy arch mismatch (blob=%u expected=%u)\n",
			hdr->arch_id, BPF_JIT_ARCH_ARM64);
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
