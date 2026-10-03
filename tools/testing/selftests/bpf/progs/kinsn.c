// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void bpf_kfunc_common_test(void)
	__ksym;

#define KINSN_SIDECAR(payload) \
	(0xb7ULL | (((payload) & 0xfULL) << 8) | (3ULL << 12) | \
	 ((((payload) >> 4) & 0xffffULL) << 16) | ((((__u64)(payload)) >> 20) << 32))
#define PACKED_PAYLOAD 0x123456781234fULL

char _license[] SEC("license") = "GPL";

void __kfunc_btf_root(void)
{
	asm volatile ("" : : "r"(&bpf_testmod_kinsn_42),
			    "r"(&bpf_testmod_kinsn_7),
			    "r"(&bpf_kfunc_common_test));
}

SEC("socket")
__success __retval(42)
__naked void basic(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void packed_payload(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(PACKED_PAYLOAD)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void forward_jump_to_region_end(void)
{
	asm volatile ("r2 = *(u32 *)(r1 + 0);"
		".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(3)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void two_regions(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void two_regions_varlen(void)
{
	asm volatile ("r2 = *(u32 *)(r1 + 0);"
		".8byte %[jump_sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		".8byte %[plain_sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(jump_sidecar, KINSN_SIDECAR(3)),
		    __imm_const(plain_sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(7)
__naked void second_kinsn_kfunc(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_7];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_7) : __clobber_all);
}

SEC("socket")
__success __retval(7)
__naked void two_kinsn_kfuncs(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_7];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_42),
		    __imm(bpf_testmod_kinsn_7) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void stack_only_in_proof(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(4)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void r6_only_in_proof(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(5)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("netfilter")
__failure __msg("calling kernel function bpf_testmod_kinsn_7 is not allowed")
__naked void filtered_kinsn(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_7];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_testmod_kinsn_7) : __clobber_all);
}

SEC("socket")
__success __retval(42)
__naked void ordinary_kfunc_then_kinsn(void)
{
	asm volatile ("call %[bpf_kfunc_common_test];"
		".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_kfunc_common_test),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__failure __msg("kinsn call must be preceded by sidecar payload")
__naked void missing_sidecar(void)
{
	asm volatile ("call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__failure __msg("kinsn sidecar must immediately precede kinsn call")
__naked void orphan_sidecar(void)
{
	asm volatile (".8byte %[sidecar];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)) : __clobber_all);
}

SEC("socket")
__failure __msg("kinsn sidecar must immediately precede kinsn call")
__naked void sidecar_before_ordinary_kfunc(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_kfunc_common_test];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(0)),
		    __imm(bpf_kfunc_common_test) : __clobber_all);
}

SEC("socket")
__failure __msg("R2 !read_ok")
__naked void unsafe_proof(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(1)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

SEC("socket")
__failure __msg("invalid kinsn proof payload")
__naked void invalid_payload(void)
{
	asm volatile (".8byte %[sidecar];"
		"call %[bpf_testmod_kinsn_42];"
		"exit;"
		: : __imm_const(sidecar, KINSN_SIDECAR(2)),
		    __imm(bpf_testmod_kinsn_42) : __clobber_all);
}

#define INVALID_PROOF_TEST(name, payload, message) \
SEC("socket") __failure __msg(message) \
__naked void name(void) \
{ \
	asm volatile ( \
		".8byte %[sidecar];" \
		"call %[bpf_testmod_kinsn_42];" \
		"exit;" \
		: : __imm_const(sidecar, KINSN_SIDECAR(payload)), \
		    __imm(bpf_testmod_kinsn_42) : __clobber_all); \
}

INVALID_PROOF_TEST(backward_proof_jump, 6,
		   "kinsn proof jump must stay forward and within its region")
INVALID_PROOF_TEST(out_of_region_proof_jump, 7,
		   "kinsn proof jump must stay forward and within its region")
INVALID_PROOF_TEST(may_goto_proof, 8,
		   "kinsn proof sequence cannot contain calls, exits, may_goto or gotox")
INVALID_PROOF_TEST(gotox_proof, 9,
		   "kinsn proof sequence cannot contain calls, exits, may_goto or gotox")
INVALID_PROOF_TEST(call_proof, 10,
		   "kinsn proof sequence cannot contain calls, exits, may_goto or gotox")
INVALID_PROOF_TEST(exit_proof, 11,
		   "kinsn proof sequence cannot contain calls, exits, may_goto or gotox")
INVALID_PROOF_TEST(pseudo_ldimm64_proof, 12,
		   "kinsn proof sequence cannot contain pseudo ldimm64")
