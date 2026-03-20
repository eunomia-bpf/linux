/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_JIT_DIRECTIVES_H
#define _LINUX_BPF_JIT_DIRECTIVES_H

#include <linux/errno.h>
#include <linux/types.h>

#if defined(BPF_JIT_MAX_CANONICAL_PARAMS) && \
	BPF_JIT_MAX_CANONICAL_PARAMS != 16
#error "BPF_JIT_MAX_CANONICAL_PARAMS must stay in sync with UAPI"
#endif
#ifndef BPF_JIT_MAX_CANONICAL_PARAMS
#define BPF_JIT_MAX_CANONICAL_PARAMS	16
#endif
#ifndef BPF_JIT_MAX_PATTERN_LEN
#define BPF_JIT_MAX_PATTERN_LEN		64
#endif

struct bpf_prog;
struct exception_table_entry;

#define BPF_JIT_REWRITE_F_ACTIVE  (1U << 0)

enum bpf_jit_binding_value_type {
	BPF_JIT_BIND_VAL_REG = 0,
	BPF_JIT_BIND_VAL_IMM = 1,
};

struct bpf_jit_binding_value {
	s64 value;
	u8 type;
};

struct bpf_jit_canonical_params {
	struct bpf_jit_binding_value params[BPF_JIT_MAX_CANONICAL_PARAMS];
};

enum bpf_jit_rotate_param {
	BPF_JIT_ROT_PARAM_DST_REG	= 0,
	BPF_JIT_ROT_PARAM_SRC_REG	= 1,
	BPF_JIT_ROT_PARAM_AMOUNT	= 2,
	BPF_JIT_ROT_PARAM_WIDTH		= 3,
};

enum bpf_jit_wide_mem_param {
	BPF_JIT_WMEM_PARAM_DST_REG	= 0,
	BPF_JIT_WMEM_PARAM_BASE_REG	= 1,
	BPF_JIT_WMEM_PARAM_BASE_OFF	= 2,
	BPF_JIT_WMEM_PARAM_WIDTH	= 3,
};

#define BPF_JIT_WMEM_WIDTH_MASK		0xffU
#define BPF_JIT_WMEM_F_BIG_ENDIAN	(1U << 8)

enum bpf_jit_addr_calc_param {
	BPF_JIT_ACALC_PARAM_DST_REG	= 0,
	BPF_JIT_ACALC_PARAM_BASE_REG	= 1,
	BPF_JIT_ACALC_PARAM_INDEX_REG	= 2,
	BPF_JIT_ACALC_PARAM_SCALE	= 3,
};

enum bpf_jit_bitfield_extract_order {
	BPF_JIT_BFX_ORDER_SHIFT_MASK = 0,
	BPF_JIT_BFX_ORDER_MASK_SHIFT = 1,
};

enum bpf_jit_bitfield_extract_param {
	BPF_JIT_BFX_PARAM_DST_REG	= 0,
	BPF_JIT_BFX_PARAM_SRC_REG	= 1,
	BPF_JIT_BFX_PARAM_SHIFT		= 2,
	BPF_JIT_BFX_PARAM_MASK		= 3,
	BPF_JIT_BFX_PARAM_WIDTH		= 4,
	BPF_JIT_BFX_PARAM_ORDER		= 5,
};

enum bpf_jit_zero_ext_param {
	BPF_JIT_ZEXT_PARAM_DST_REG	= 0,
	BPF_JIT_ZEXT_PARAM_CODE		= 1,
	BPF_JIT_ZEXT_PARAM_SRC_REG	= 2,
	BPF_JIT_ZEXT_PARAM_OFF		= 3,
	BPF_JIT_ZEXT_PARAM_IMM		= 4,
};

enum bpf_jit_cond_select_param {
	BPF_JIT_SEL_PARAM_DST_REG	= 0,
	BPF_JIT_SEL_PARAM_COND_OP	= 1,
	BPF_JIT_SEL_PARAM_COND_A	= 2,
	BPF_JIT_SEL_PARAM_COND_B	= 3,
	BPF_JIT_SEL_PARAM_TRUE_VAL	= 4,
	BPF_JIT_SEL_PARAM_FALSE_VAL	= 5,
	BPF_JIT_SEL_PARAM_WIDTH		= 6,
};

enum bpf_jit_endian_fusion_direction {
	BPF_JIT_ENDIAN_LOAD_SWAP	= 0,
	BPF_JIT_ENDIAN_SWAP_STORE	= 1,
};

enum bpf_jit_endian_fusion_param {
	BPF_JIT_ENDIAN_PARAM_DATA_REG	= 0,
	BPF_JIT_ENDIAN_PARAM_BASE_REG	= 1,
	BPF_JIT_ENDIAN_PARAM_OFFSET	= 2,
	BPF_JIT_ENDIAN_PARAM_WIDTH	= 3,
	BPF_JIT_ENDIAN_PARAM_DIRECTION	= 4,
};

enum bpf_jit_branch_flip_param {
	BPF_JIT_BFLIP_PARAM_COND_CODE	= 0,
	BPF_JIT_BFLIP_PARAM_COND_DST_REG = 1,
	BPF_JIT_BFLIP_PARAM_COND_SRC	= 2,
	BPF_JIT_BFLIP_PARAM_BODY_A_LEN	= 3,
	BPF_JIT_BFLIP_PARAM_BODY_A_PTR	= 4,
	BPF_JIT_BFLIP_PARAM_BODY_B_LEN	= 5,
	BPF_JIT_BFLIP_PARAM_BODY_B_PTR	= 6,
};

/**
 * struct bpf_jit_rule - validated v5 rewrite rule (kernel-internal)
 * @canonical_form: canonical emitter target
 * @native_choice:  requested native emission mode
 * @params:         canonical parameters synthesized by per-form validators
 * @site_start:     BPF insn offset (in xlated program)
 * @site_len:       how many BPF insns this rule covers
 * @flags:          BPF_JIT_REWRITE_F_*
 * @user_index:     original blob order for logging/tie-breaks
 */
struct bpf_jit_rule {
	u16 canonical_form;
	u16 native_choice;
	struct bpf_jit_canonical_params params;
	u32 site_start;
	u16 site_len;
	u16 flags;
	u16 user_index;
};

/**
 * struct bpf_jit_policy - validated policy attached to a prog
 * @rule_cnt:   number of rules
 * @active_cnt: number of rules that passed validation
 * @blob:       retained v5 blob backing inline pattern pointers
 * @rules:      sorted by site_start for O(log n) lookup
 */
struct bpf_jit_policy {
	u32 rule_cnt;
	u32 active_cnt;
	void *blob;
	struct bpf_jit_rule rules[];
};

/* Syscall handler */
int bpf_prog_jit_recompile(union bpf_attr *attr);
void __printf(2, 3) bpf_jit_recompile_prog_log(const struct bpf_prog *prog,
					       const char *fmt, ...);
void __printf(3, 4) bpf_jit_recompile_rule_log(const struct bpf_prog *prog,
					       const struct bpf_jit_rule *rule,
					       const char *fmt, ...);
void bpf_jit_recompile_note_rule(const struct bpf_prog *prog,
				 const struct bpf_jit_rule *rule,
				 bool applied);

/* Policy blob parsing & validation */
struct bpf_jit_policy *bpf_jit_parse_policy(struct bpf_prog *prog, int fd);
void bpf_jit_free_policy(struct bpf_jit_policy *policy);

/* Rule lookup during JIT emission by absolute rule site_start. */
const struct bpf_jit_rule *
bpf_jit_rule_lookup(const struct bpf_jit_policy *policy, u32 insn_idx);

#if defined(CONFIG_X86_64)
bool bpf_jit_recompile_has_staged_image(const struct bpf_prog *prog);
void *bpf_jit_recompile_staged_func(const struct bpf_prog *prog);
u32 bpf_jit_recompile_staged_len(const struct bpf_prog *prog);
u32 bpf_jit_recompile_staged_fp_start(const struct bpf_prog *prog);
u32 bpf_jit_recompile_staged_fp_end(const struct bpf_prog *prog);
struct exception_table_entry *
bpf_jit_recompile_staged_extable(const struct bpf_prog *prog);
u32 bpf_jit_recompile_staged_num_exentries(const struct bpf_prog *prog);
int bpf_jit_recompile_commit(struct bpf_prog *prog);
void bpf_jit_recompile_abort(struct bpf_prog *prog);
#else
static inline bool
bpf_jit_recompile_has_staged_image(const struct bpf_prog *prog)
{
	return false;
}

static inline void *bpf_jit_recompile_staged_func(const struct bpf_prog *prog)
{
	return NULL;
}

static inline u32 bpf_jit_recompile_staged_len(const struct bpf_prog *prog)
{
	return 0;
}

static inline u32 bpf_jit_recompile_staged_fp_start(const struct bpf_prog *prog)
{
	return 0;
}

static inline u32 bpf_jit_recompile_staged_fp_end(const struct bpf_prog *prog)
{
	return 0;
}

static inline struct exception_table_entry *
bpf_jit_recompile_staged_extable(const struct bpf_prog *prog)
{
	return NULL;
}

static inline u32
bpf_jit_recompile_staged_num_exentries(const struct bpf_prog *prog)
{
	return 0;
}

static inline int bpf_jit_recompile_commit(struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline void bpf_jit_recompile_abort(struct bpf_prog *prog)
{
}
#endif

#endif /* _LINUX_BPF_JIT_DIRECTIVES_H */
