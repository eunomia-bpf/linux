// SPDX-License-Identifier: GPL-2.0
/* LOCAL benchmark, not part of the series */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern __u64 bpf_rol64(__u64 x, __u32 n) __ksym;
extern __u64 bpf_select64(__u64 cond, __u64 a, __u64 b) __ksym;

#define N 1024

__u64 seed, out;

static __always_inline __u64 rol_c(__u64 x, __u32 n)
{
	return x << n | x >> (64 - n);
}

/* 2 dependent rotates per iteration */
SEC("tc")
int rol_plain(void *ctx)
{
	__u64 x = seed;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < N; i++) {
		x = rol_c(x, 13) + i;
		x = rol_c(x, 29) ^ i;
	}
	out = x;
	seed = x;
	return 0;
}

SEC("tc")
int rol_kfunc(void *ctx)
{
	__u64 x = seed;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < N; i++) {
		x = bpf_rol64(x, 13) + i;
		x = bpf_rol64(x, 29) ^ i;
	}
	out = x;
	seed = x;
	return 0;
}

/* 1 select per iteration on an unpredictable condition */
SEC("tc")
int sel_plain(void *ctx)
{
	__u64 x = seed, acc = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < N; i++) {
		x = x * 0x9e3779b97f4a7c15ULL + i;
		acc = (x >> 63) ? acc + x : acc ^ x;
	}
	out = acc;
	seed = x;
	return 0;
}

SEC("tc")
int sel_kfunc(void *ctx)
{
	__u64 x = seed, acc = 0;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < N; i++) {
		x = x * 0x9e3779b97f4a7c15ULL + i;
		acc = bpf_select64(x >> 63, acc + x, acc ^ x);
	}
	out = acc;
	seed = x;
	return 0;
}


/* 4 independent rotates per iteration */
#define ROL4(rol)							\
	__u64 a = seed, b = seed + 1, c = seed + 2, d = seed + 3;	\
	int i;								\
									\
	_Pragma("clang loop unroll(disable)")				\
	for (i = 0; i < N; i++) {					\
		a = rol(a, 13) + i;					\
		b = rol(b, 17) + i;					\
		c = rol(c, 29) + i;					\
		d = rol(d, 41) + i;					\
	}								\
	out = a ^ b ^ c ^ d;						\
	seed = out;							\
	return 0;

SEC("tc")
int rol4_plain(void *ctx)
{
	ROL4(rol_c)
}

SEC("tc")
int rol4_kfunc(void *ctx)
{
	ROL4(bpf_rol64)
}

/* 4 independent selects per iteration */
#define SEL4(sel)							\
	__u64 x = seed, a = 0, b = 1, c = 2, d = 3;			\
	int i;								\
									\
	_Pragma("clang loop unroll(disable)")				\
	for (i = 0; i < N; i++) {					\
		x = x * 0x9e3779b97f4a7c15ULL + i;			\
		a = sel(x >> 63, a + x, a ^ x);				\
		b = sel(x & 1, b + x, b ^ x);				\
		c = sel((x >> 31) & 1, c + x, c ^ x);			\
		d = sel((x >> 47) & 1, d + x, d ^ x);			\
	}								\
	out = a ^ b ^ c ^ d;						\
	seed = x;							\
	return 0;

#define sel_c(cond, p, q) ((cond) ? (p) : (q))

SEC("tc")
int sel4_plain(void *ctx)
{
	SEL4(sel_c)
}

SEC("tc")
int sel4_kfunc(void *ctx)
{
	SEL4(bpf_select64)
}

char _license[] SEC("license") = "GPL";
