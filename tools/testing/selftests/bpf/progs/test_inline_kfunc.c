// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern __u64 bpf_test_add42(__u64 val) __ksym;

SEC("xdp")
int inline_kfunc(struct xdp_md *ctx)
{
	return bpf_test_add42(100) == 142 ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
