// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <uapi/linux/fcntl.h>

#define BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE	SZ_64K

static bool bpf_jit_directives_valid_memfd(struct file *file)
{
	int seals;

	seals = memfd_fcntl(file, F_GET_SEALS, 0);
	if (seals < 0)
		return false;

	return (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) ==
	       (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK);
}

static bool bpf_jit_directive_supported(const struct bpf_jit_directive_rec *rec,
					u32 insn_cnt)
{
	if (rec->reserved || rec->site_idx >= insn_cnt)
		return false;

	switch (rec->kind) {
	case BPF_JIT_DIRECTIVE_WIDE_LOAD:
		return true;
	default:
		return false;
	}
}

struct bpf_jit_directive_state *
bpf_jit_directives_load(struct bpf_prog *prog, int fd, u32 flags)
{
	const struct bpf_jit_directive_hdr *hdr;
	struct bpf_jit_directive_state *state = NULL;
	const struct bpf_jit_directive_rec *recs;
	struct fd f = fdget(fd);
	size_t blob_len, expected_len;
	void *blob = NULL;
	loff_t pos = 0;
	ssize_t nread;
	u32 kept = 0;
	u32 i;

	if (fd_empty(f) || !prog)
		goto out;

	if (flags & ~BPF_F_JIT_DIRECTIVES_LOG)
		goto out;

	if (!bpf_jit_directives_valid_memfd(fd_file(f)))
		goto out;

	blob_len = i_size_read(file_inode(fd_file(f)));
	if (!blob_len || blob_len > BPF_JIT_DIRECTIVES_MAX_BLOB_SIZE)
		goto out;

	blob = kvzalloc(blob_len, GFP_KERNEL_ACCOUNT);
	if (!blob)
		goto out;

	nread = kernel_read(fd_file(f), blob, blob_len, &pos);
	if (nread != blob_len)
		goto out;

	hdr = blob;
	if (blob_len < sizeof(*hdr))
		goto out;
	if (hdr->magic != BPF_JIT_DIRECTIVE_MAGIC ||
	    hdr->version != BPF_JIT_DIRECTIVE_VERSION ||
	    hdr->rec_size != sizeof(struct bpf_jit_directive_rec) ||
	    hdr->insn_cnt != prog->len)
		goto out;

	expected_len = sizeof(*hdr) +
		       array_size(sizeof(struct bpf_jit_directive_rec),
				  hdr->rec_cnt);
	if (expected_len != blob_len)
		goto out;

	recs = (const struct bpf_jit_directive_rec *)(hdr + 1);
	for (i = 0; i < hdr->rec_cnt; i++) {
		if (bpf_jit_directive_supported(&recs[i], prog->len))
			kept++;
	}

	if (!kept)
		goto out;

	state = kvmalloc(struct_size(state, recs, kept), GFP_KERNEL_ACCOUNT);
	if (!state)
		goto out;

	state->rec_cnt = kept;
	state->applied_cnt = 0;
	kept = 0;
	for (i = 0; i < hdr->rec_cnt; i++) {
		if (!bpf_jit_directive_supported(&recs[i], prog->len))
			continue;

		state->recs[kept].kind = recs[i].kind;
		state->recs[kept].site_idx = recs[i].site_idx;
		state->recs[kept].payload = recs[i].payload;
		kept++;
	}

out:
	kvfree(blob);
	fdput(f);
	return state;
}

void bpf_jit_directives_free(struct bpf_jit_directive_state *state)
{
	kvfree(state);
}
