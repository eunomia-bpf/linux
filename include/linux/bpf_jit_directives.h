/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_JIT_DIRECTIVES_H
#define _LINUX_BPF_JIT_DIRECTIVES_H

#include <linux/types.h>

struct bpf_prog;
struct bpf_verifier_env;

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

#endif /* _LINUX_BPF_JIT_DIRECTIVES_H */
