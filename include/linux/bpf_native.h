/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_NATIVE_H
#define _LINUX_BPF_NATIVE_H

#include <linux/types.h>

struct bpf_prog;

#define BPF_NATIVE_RELOC_CALL_REL32	1
#define BPF_NATIVE_RELOC_ARM64_CALL	2
#define BPF_NATIVE_RELOC_ARM64_BL26	3
#define BPF_NATIVE_RELOC_ARM64_PERCPU	4
#define BPF_NATIVE_RELOC_EXCLUSIVE_FAILURE 9
#define BPF_NATIVE_ARM64_LOAD	(1U << 26)
#define BPF_NATIVE_ARM64_PAIR	(1U << 25)
#define BPF_NATIVE_RELOC_X86_TAIL_COUNT	10
#define BPF_NATIVE_RELOC_X86_TAIL_STACK	11
#define BPF_NATIVE_RELOC_MAP_POINTER	5
#define BPF_NATIVE_RELOC_MAP_VALUE	6
#define BPF_NATIVE_RELOC_HELPER_POINTER	7
#define BPF_NATIVE_RELOC_READONLY_DATA	8

struct bpf_native_reloc {
	u32 offset, kind;
	u64 target;
};

/* Exception-table site: offset within the image, ex->fixup word. */
struct bpf_native_site {
	u32 offset, fixup;
};

struct bpf_native_image {
	const u8 *bytes;
	const struct bpf_native_reloc *relocs;
	const struct bpf_native_site *sites;
	u32 len, nr_relocs, nr_sites, callee_saved_mask;
};

void bpf_native_image_arm(struct bpf_native_image *image);
void bpf_native_image_free(struct bpf_native_image *image);
int bpf_native_image_bind(struct bpf_prog *prog);
struct bpf_native_image *bpf_native_image_take(const struct bpf_prog *prog);

#endif
