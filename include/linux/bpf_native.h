/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_NATIVE_H
#define _LINUX_BPF_NATIVE_H

#include <linux/types.h>

struct task_struct;

#define BPF_NATIVE_RELOC_CALL_REL32	1
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
	u32 len, nr_relocs, nr_sites;
	struct task_struct *owner;
};

void bpf_native_image_arm(struct bpf_native_image *image);

#endif
