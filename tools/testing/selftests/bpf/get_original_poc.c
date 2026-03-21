// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ptr_to_u64(ptr) ((__u64)(uintptr_t)(ptr))

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int load_test_prog(char *log_buf, size_t log_buf_sz)
{
	static struct bpf_insn insns[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = XDP_PASS,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	static const char license[] = "GPL";
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64(license);
	attr.log_level = 1;
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_buf_sz;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int main(void)
{
	static struct bpf_insn expected[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = XDP_PASS,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	struct bpf_insn got[ARRAY_SIZE(expected)];
	struct bpf_prog_info info;
	char log_buf[65536];
	union bpf_attr attr;
	int prog_fd;

	memset(log_buf, 0, sizeof(log_buf));
	prog_fd = load_test_prog(log_buf, sizeof(log_buf));
	if (prog_fd < 0) {
		fprintf(stderr, "BPF_PROG_LOAD failed: %s\n%s\n",
			strerror(errno), log_buf);
		return 1;
	}

	memset(&info, 0, sizeof(info));
	memset(got, 0, sizeof(got));
	info.orig_prog_len = sizeof(got);
	info.orig_prog_insns = ptr_to_u64(got);

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = ptr_to_u64(&info);

	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
		fprintf(stderr, "BPF_OBJ_GET_INFO_BY_FD failed: %s\n",
			strerror(errno));
		close(prog_fd);
		return 1;
	}

	close(prog_fd);

	if (info.orig_prog_len != sizeof(expected)) {
		fprintf(stderr, "unexpected orig_prog_len %u\n", info.orig_prog_len);
		return 1;
	}

	if (memcmp(got, expected, sizeof(expected)) != 0) {
		fprintf(stderr, "original insns mismatch\n");
		return 1;
	}

	printf("orig_prog_len=%u bytes, original insns match\n", info.orig_prog_len);
	return 0;
}
