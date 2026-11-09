// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/module.h>

struct bpf_test_kinsn_pair {
	u64 a, b;
};

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_test_kinsn(u64 x)
{
	return x;
}

__bpf_kfunc u64 bpf_test_kinsn_unset(u64 x)
{
	return x;
}

__bpf_kfunc u64 bpf_test_kinsn_pair(struct bpf_test_kinsn_pair p)
{
	return p.a;
}

__bpf_kfunc u64 bpf_test_kinsn_sleepable(u64 x)
{
	return x;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(test_kinsn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_kinsn)
BTF_KFUNCS_END(test_kinsn_kfunc_ids)

/* never registered */
BTF_KFUNCS_START(test_kinsn_bad_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_kinsn_pair)
BTF_ID_FLAGS(func, bpf_test_kinsn_sleepable, KF_SLEEPABLE)
BTF_KFUNCS_END(test_kinsn_bad_kfunc_ids)

BTF_ID_LIST(test_kinsn_ids)
BTF_ID(func, bpf_test_kinsn)
BTF_ID(func, bpf_test_kinsn_unset)
BTF_ID(func, bpf_test_kinsn_pair)
BTF_ID(func, bpf_test_kinsn_sleepable)

static const struct bpf_insn test_kinsn_insns[] = {
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
};

/* writes R6 */
static const struct bpf_insn test_kinsn_bad_insns[] = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
};

/* jumps past the last instruction */
static const struct bpf_insn test_kinsn_jump_insns[] = {
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
	BPF_MOV64_IMM(BPF_REG_0, 0),
};

static struct bpf_kinsn test_kinsn = { .id = &test_kinsn_ids[0] };

static struct btf_kfunc_id_set test_kinsn_set = {
	.owner = THIS_MODULE,
	.set = &test_kinsn_kfunc_ids,
	.kinsns = &test_kinsn,
	.kinsn_cnt = 1,
};

static int test_kinsn_rejected(struct btf_id_set8 *set, const u32 *id,
			       const struct bpf_insn *insns, u32 len)
{
	test_kinsn_set.set = set;
	test_kinsn.id = id;
	test_kinsn.insns = insns;
	test_kinsn.len = len;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &test_kinsn_set) == -EINVAL;
}

/*
 * The module loads only if registration rejects a kinsn without instructions,
 * one with an instruction that writes R6, one with a jump past its last
 * instruction, one for a kfunc outside the set, one with an argument of two
 * registers and one for a kfunc with flags.
 */
static int bpf_test_kinsn_init(void)
{
	struct btf_id_set8 *good = &test_kinsn_kfunc_ids, *bad = &test_kinsn_bad_kfunc_ids;

	if (!test_kinsn_rejected(good, &test_kinsn_ids[0], NULL, 0) ||
	    !test_kinsn_rejected(good, &test_kinsn_ids[0], test_kinsn_bad_insns,
				 ARRAY_SIZE(test_kinsn_bad_insns)) ||
	    !test_kinsn_rejected(good, &test_kinsn_ids[0], test_kinsn_jump_insns,
				 ARRAY_SIZE(test_kinsn_jump_insns)) ||
	    !test_kinsn_rejected(good, &test_kinsn_ids[1], test_kinsn_insns, 1) ||
	    !test_kinsn_rejected(bad, &test_kinsn_ids[2], test_kinsn_insns, 1) ||
	    !test_kinsn_rejected(bad, &test_kinsn_ids[3], test_kinsn_insns, 1))
		return -EINVAL;
	test_kinsn_set.set = good;
	test_kinsn.id = &test_kinsn_ids[0];
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &test_kinsn_set);
}

static void bpf_test_kinsn_exit(void)
{
}

module_init(bpf_test_kinsn_init);
module_exit(bpf_test_kinsn_exit);

MODULE_DESCRIPTION("BPF kinsn registration test module");
MODULE_LICENSE("GPL");
