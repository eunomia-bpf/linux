// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <testing_helpers.h>

/* bpf_test_kinsn.ko fails to load unless bad kinsns are rejected */
void test_kinsn_registration(void)
{
	int fd, err;

	fd = open("bpf_test_kinsn.ko", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open"))
		return;
	err = finit_module(fd, "", 0);
	close(fd);
	if (!ASSERT_OK(err, "finit_module"))
		return;
	ASSERT_OK(delete_module("bpf_test_kinsn", 0), "delete_module");
}
