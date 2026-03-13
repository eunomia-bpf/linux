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

struct bpf_prog;
struct exception_table_entry;
struct bpf_jit_pattern_insn;
struct bpf_jit_pattern_constraint;
struct bpf_jit_binding;

#define BPF_JIT_REWRITE_F_ACTIVE  (1U << 0)

enum bpf_jit_var_type {
	BPF_JIT_VAR_NONE = 0,
	BPF_JIT_VAR_REG,
	BPF_JIT_VAR_IMM,
	BPF_JIT_VAR_OFF,
};

struct bpf_jit_var {
	s64 value;
	u8 type;
	bool bound;
};

enum bpf_jit_binding_value_type {
	BPF_JIT_BIND_VAL_REG = 0,
	BPF_JIT_BIND_VAL_IMM = 1,
};

struct bpf_jit_binding_value {
	s64 value;
	u8 type;
	u8 reserved[7];
};

struct bpf_jit_canonical_params {
	struct bpf_jit_binding_value params[BPF_JIT_MAX_CANONICAL_PARAMS];
	u32 present_mask;
	u8 param_count;
};

/**
 * struct bpf_jit_rule - validated v5 rewrite rule (kernel-internal)
 * @rule_kind:       enum bpf_jit_rule_kind (BPF_JIT_RK_PATTERN only)
 * @canonical_form:  canonical emitter target
 * @native_choice:   requested native emission mode
 * @pattern_count:   pattern length
 * @constraint_count: arithmetic constraint count
 * @binding_count:   canonical binding count
 * @pattern:         inline pattern array stored in policy->blob
 * @constraints:     inline constraint array stored in policy->blob
 * @bindings:        inline canonical binding array stored in policy->blob
 * @params:          extracted canonical parameters for emitters
 * @site_start:      BPF insn offset (in xlated program)
 * @site_len:        how many BPF insns this rule covers
 * @flags:           BPF_JIT_REWRITE_F_*
 * @priority:        higher wins on overlap
 */
struct bpf_jit_rule {
	u16 rule_kind;
	u16 canonical_form;
	u16 native_choice;
	u16 pattern_count;
	u16 constraint_count;
	u16 binding_count;
	u16 reserved;
	const struct bpf_jit_pattern_insn *pattern;
	const struct bpf_jit_pattern_constraint *constraints;
	const struct bpf_jit_binding *bindings;
	struct bpf_jit_canonical_params params;
	u32 site_start;
	u16 site_len;
	u16 flags;
	u16 priority;
	u16 user_index;
	u32 cpu_features_required;
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
