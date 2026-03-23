// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_test_add42(u64 val)
{
	return val + 42;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_test_inline_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_add42, KF_KINSN);
BTF_KFUNCS_END(bpf_test_inline_kfunc_ids)

static const struct btf_kfunc_id_set bpf_test_inline_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_test_inline_kfunc_ids,
};

static int emit_add42_x86(u8 *image, u32 *off, bool emit,
			  const struct bpf_kinsn_call *call,
			  struct bpf_prog *prog)
{
	static const u8 insns[] = {
		0x48, 0x89, 0xf8,	/* mov rax, rdi */
		0x48, 0x83, 0xc0, 0x2a,	/* add rax, 42 */
	};

	if (!off)
		return -EINVAL;
	if (emit && !image)
		return -EINVAL;

	(void)call;
	(void)prog;

	if (emit)
		memcpy(image + *off, insns, sizeof(insns));

	*off += sizeof(insns);
	return sizeof(insns);
}

static int model_add42_call(const struct bpf_kinsn_call *call,
			    const struct bpf_kinsn_scalar_state *scalar_regs,
			    struct bpf_kinsn_effect *effect)
{
	(void)call;
	(void)scalar_regs;

	effect->input_mask = BIT(BPF_REG_1);
	effect->clobber_mask = BIT(BPF_REG_0);
	effect->result_type = BPF_KINSN_RES_SCALAR;
	effect->result_reg = BPF_REG_0;
	effect->result_size = sizeof(u64);
	return 0;
}

static const struct bpf_kinsn_ops add42_ops = {
	.owner = THIS_MODULE,
	.api_version = 1,
	.supported_encodings = BPF_KINSN_ENC_LEGACY_KFUNC,
	.model_call = model_add42_call,
	.emit_x86 = emit_add42_x86,
	.max_emit_bytes = 16,
};

static int __init bpf_test_inline_kfunc_init(void)
{
	int ret;

	ret = bpf_register_kinsn_ops("bpf_test_add42", &add42_ops);
	if (ret)
		return ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&bpf_test_inline_kfunc_set);
	if (ret)
		bpf_unregister_kinsn_ops("bpf_test_add42");

	return ret;
}

static void __exit bpf_test_inline_kfunc_exit(void)
{
	bpf_unregister_kinsn_ops("bpf_test_add42");
}

module_init(bpf_test_inline_kfunc_init);
module_exit(bpf_test_inline_kfunc_exit);

MODULE_DESCRIPTION("BPF selftest inline kfunc module");
MODULE_LICENSE("GPL");
