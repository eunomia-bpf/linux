// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <testing_helpers.h>

#include "test_inline_kfunc.skel.h"

static int get_jited_program(int prog_fd, __u8 **buf, __u32 *len)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	__u32 jited_len;
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err)
		return err;
	if (!info.jited_prog_len)
		return -ENOENT;
	jited_len = info.jited_prog_len;

	*buf = calloc(jited_len, 1);
	if (!*buf)
		return -ENOMEM;

	memset(&info, 0, sizeof(info));
	info.jited_prog_len = jited_len;
	info.jited_prog_insns = ptr_to_u64(*buf);
	*len = jited_len;
	info_len = sizeof(info);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		free(*buf);
		*buf = NULL;
		*len = 0;
	}

	return err;
}

static bool find_bytes(const __u8 *haystack, __u32 haystack_len,
		       const __u8 *needle, __u32 needle_len)
{
	__u32 i;

	if (!needle_len || haystack_len < needle_len)
		return false;

	for (i = 0; i <= haystack_len - needle_len; i++) {
		if (!memcmp(haystack + i, needle, needle_len))
			return true;
	}

	return false;
}

void test_inline_kfunc(void)
{
	static const __u8 inline_seq[] = {
		0x48, 0x89, 0xf8,
		0x48, 0x83, 0xc0, 0x2a,
	};
	struct test_inline_kfunc *skel = NULL;
	__u8 pkt[64] = {};
	__u8 *jited = NULL;
	__u32 jited_len = 0;
	int err, prog_fd;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = pkt,
			    .data_size_in = sizeof(pkt));

	err = load_module("bpf_test_inline_kfunc.ko",
			  env_verbosity > VERBOSE_NONE);
	if (!ASSERT_OK(err, "load bpf_test_inline_kfunc.ko"))
		return;

	skel = test_inline_kfunc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_inline_kfunc__open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.inline_kfunc);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		goto cleanup;
	if (!ASSERT_EQ(opts.retval, XDP_PASS, "retval"))
		goto cleanup;

	err = get_jited_program(prog_fd, &jited, &jited_len);
	if (!ASSERT_OK(err, "get_jited_program"))
		goto cleanup;
	ASSERT_TRUE(find_bytes(jited, jited_len, inline_seq, sizeof(inline_seq)),
		    "inline sequence present");

cleanup:
	free(jited);
	test_inline_kfunc__destroy(skel);
	unload_module("bpf_test_inline_kfunc", env_verbosity > VERBOSE_NONE);
}
