// SPDX-License-Identifier: GPL-2.0
/* LOCAL benchmark, not part of the series */
#include <test_progs.h>
#include <network_helpers.h>
#include "kfunc_inline_bench.skel.h"

#define N	1024
#define ROUNDS	7

static void bench(struct bpf_program *prog, int ops_per_iter)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 20000,
	);
	__u32 best = ~0U, d[ROUNDS];
	int i, fd = bpf_program__fd(prog);

	for (i = 0; i < ROUNDS; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run"))
			return;
		d[i] = opts.duration;
		if (opts.duration < best)
			best = opts.duration;
	}
	printf("BENCH %-10s ns/run min %u (%.3f ns/op) rounds:", bpf_program__name(prog), best,
	       (double)best / (N * ops_per_iter));
	for (i = 0; i < ROUNDS; i++)
		printf(" %u", d[i]);
	printf("\n");
}

void test_kfunc_inline_bench(void)
{
	struct kfunc_inline_bench *skel;

	skel = kfunc_inline_bench__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	skel->bss->seed = 0x0123456789abcdefULL;
	bench(skel->progs.rol_plain, 2);
	bench(skel->progs.rol_kfunc, 2);
	bench(skel->progs.sel_plain, 1);
	bench(skel->progs.sel_kfunc, 1);
	bench(skel->progs.rol4_plain, 4);
	bench(skel->progs.rol4_kfunc, 4);
	bench(skel->progs.sel4_plain, 4);
	bench(skel->progs.sel4_kfunc, 4);
	kfunc_inline_bench__destroy(skel);
}
