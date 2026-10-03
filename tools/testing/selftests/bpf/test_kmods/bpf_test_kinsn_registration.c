// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/module.h>

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_test_kinsn_flagged(void)
{
	return 42;
}

__bpf_kfunc_end_defs();

static int flagged_kinsn_proof(u64 payload, struct bpf_insn *insns)
{
	if (payload)
		return -EINVAL;
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 42);
	return 1;
}

static const struct bpf_kinsn flagged_kinsn = {
	.owner = THIS_MODULE,
	.max_insn_cnt = 1,
	.max_emit_bytes = 8,
	.instantiate_insn = flagged_kinsn_proof,
};

BTF_KFUNCS_START(flagged_kinsn_ids)
BTF_ID_FLAGS(func, bpf_test_kinsn_flagged, KF_SLEEPABLE)
BTF_KFUNCS_END(flagged_kinsn_ids)

BTF_ID_LIST(flagged_kinsn_list)
BTF_ID(func, bpf_test_kinsn_flagged)

static const struct bpf_kinsn * const flagged_kinsns[] = {
	&flagged_kinsn,
};

static const struct btf_kfunc_id_set flagged_kinsn_set = {
	.owner = THIS_MODULE,
	.set = &flagged_kinsn_ids,
	.kinsn_descs = flagged_kinsns,
	.kinsn_ids = flagged_kinsn_list,
	.kinsn_cnt = ARRAY_SIZE(flagged_kinsns),
};

static int __init bpf_test_kinsn_registration_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &flagged_kinsn_set);
	return ret == -EINVAL ? 0 : ret ?: -EINVAL;
}

static void __exit bpf_test_kinsn_registration_exit(void)
{
}

module_init(bpf_test_kinsn_registration_init);
module_exit(bpf_test_kinsn_registration_exit);

MODULE_DESCRIPTION("BPF flagged kinsn registration test module");
MODULE_LICENSE("GPL");
