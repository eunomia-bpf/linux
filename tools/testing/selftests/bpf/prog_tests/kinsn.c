// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kinsn.skel.h"

void test_kinsn(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	RUN_TESTS(kinsn);
#else
	test__skip(); /* This architecture has no kinsn emitter. */
#endif
}
