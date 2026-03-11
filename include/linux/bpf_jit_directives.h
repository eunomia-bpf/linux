/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_JIT_DIRECTIVES_H
#define _LINUX_BPF_JIT_DIRECTIVES_H

#include <linux/types.h>

#ifndef BPF_JIT_MAX_CANONICAL_PARAMS
#define BPF_JIT_MAX_CANONICAL_PARAMS 12
#endif

struct bpf_prog;
struct bpf_verifier_env;
struct bpf_jit_pattern_insn;
struct bpf_jit_pattern_constraint;
struct bpf_jit_binding;

/* ---- v2 legacy (BPF_PROG_LOAD path) ---- */

#define BPF_JIT_DIRECTIVE_F_VALIDATED (1U << 0)

struct bpf_jit_directive {
	u16 kind;
	u16 flags;
	u32 site_idx;
	u32 subprog_idx;
	u32 insn_idx;
	u64 payload;
};

struct bpf_jit_directive_state {
	u32 rec_cnt;
	u32 validated_cnt;
	struct bpf_jit_directive recs[];
};

struct bpf_jit_directive_state *
bpf_jit_directives_load(struct bpf_prog *prog, int fd, u32 flags);
void bpf_jit_directives_free(struct bpf_jit_directive_state *state);
int bpf_jit_directives_validate(struct bpf_verifier_env *env);
const struct bpf_jit_directive *
bpf_jit_directive_lookup(const struct bpf_prog *prog, u16 kind, u32 insn_idx);

/* ---- v4 JIT rewrite rule framework (BPF_PROG_JIT_RECOMPILE path) ---- */

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
	u16 present_mask;
	u8 param_count;
};

/**
 * struct bpf_jit_rule - validated rewrite rule (kernel-internal)
 * @rule_kind:     enum bpf_jit_rule_kind
 * @canonical_form: v5 canonical emitter target (0 for legacy v4 rules)
 * @native_choice: which native emission to use
 * @site_start:    BPF insn offset (in xlated program)
 * @site_len:      how many BPF insns this rule covers
 * @pattern_count: v5 pattern length (0 for legacy v4 rules)
 * @constraint_count: v5 arithmetic constraint count
 * @binding_count: v5 canonical binding count
 * @pattern:       v5 inline pattern array stored in policy->blob
 * @constraints:   v5 constraint array stored in policy->blob
 * @bindings:      v5 canonical binding array stored in policy->blob
 * @params:        extracted canonical parameters for v5 emitters
 * @flags:         BPF_JIT_REWRITE_F_*
 * @priority:      higher wins on overlap
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
	u32 cpu_features_required;
};

/**
 * struct bpf_jit_policy - validated policy attached to a prog
 * @rule_cnt:  number of rules
 * @active_cnt: number of rules that passed validation
 * @blob:      retained v5 blob backing inline pattern pointers
 * @rules:     sorted by site_start for O(log n) lookup
 */
struct bpf_jit_policy {
	u32 rule_cnt;
	u32 active_cnt;
	void *blob;
	struct bpf_jit_rule rules[];
};

/* Syscall handler */
int bpf_prog_jit_recompile(union bpf_attr *attr);

/* Policy blob parsing & validation */
struct bpf_jit_policy *bpf_jit_parse_policy(struct bpf_prog *prog, int fd);
void bpf_jit_free_policy(struct bpf_jit_policy *policy);

/* Rule lookup during JIT emission */
const struct bpf_jit_rule *
bpf_jit_rule_lookup(const struct bpf_jit_policy *policy, u32 insn_idx);

#endif /* _LINUX_BPF_JIT_DIRECTIVES_H */
