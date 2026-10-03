// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <testing_helpers.h>

void test_kinsn_registration(void)
{
	int fd, err;

	fd = open("bpf_test_kinsn_registration.ko", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open"))
		return;

	err = finit_module(fd, "", 0);
	close(fd);
	if (!ASSERT_OK(err, "finit_module"))
		return;

	err = delete_module("bpf_test_kinsn_registration", 0);
	ASSERT_OK(err, "delete_module");
}
