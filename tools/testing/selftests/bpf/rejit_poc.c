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

static int load_xdp_prog(const struct bpf_insn *insns, __u32 insn_cnt,
			 char *log_buf, size_t log_buf_sz)
{
	static const char license[] = "GPL";
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt = insn_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64(license);
	attr.log_level = 1;
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_buf_sz;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int rejit_xdp_prog(int prog_fd, const struct bpf_insn *insns,
			  __u32 insn_cnt, char *log_buf, size_t log_buf_sz)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.rejit.prog_fd = prog_fd;
	attr.rejit.insn_cnt = insn_cnt;
	attr.rejit.insns = ptr_to_u64(insns);
	attr.rejit.log_level = 1;
	attr.rejit.log_buf = ptr_to_u64(log_buf);
	attr.rejit.log_size = log_buf_sz;

	return sys_bpf(BPF_PROG_REJIT, &attr, sizeof(attr));
}

static int test_run_xdp_prog(int prog_fd, __u32 *retval)
{
	unsigned char data[64] = {};
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = prog_fd;
	attr.test.data_in = ptr_to_u64(data);
	attr.test.data_size_in = sizeof(data);
	attr.test.repeat = 1;

	if (sys_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr)) < 0)
		return -1;

	*retval = attr.test.retval;
	return 0;
}

int main(void)
{
	static const struct bpf_insn prog_a[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = XDP_PASS,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	static const struct bpf_insn prog_b[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = XDP_DROP,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char log_buf[65536];
	__u32 retval = 0;
	int prog_fd;

	memset(log_buf, 0, sizeof(log_buf));
	prog_fd = load_xdp_prog(prog_a, ARRAY_SIZE(prog_a), log_buf, sizeof(log_buf));
	if (prog_fd < 0) {
		fprintf(stderr, "BPF_PROG_LOAD failed: %s\n%s\n",
			strerror(errno), log_buf);
		return 1;
	}

	if (test_run_xdp_prog(prog_fd, &retval) < 0) {
		fprintf(stderr, "BPF_PROG_TEST_RUN before rejit failed: %s\n",
			strerror(errno));
		close(prog_fd);
		return 1;
	}

	if (retval != XDP_PASS) {
		fprintf(stderr, "unexpected pre-rejit retval %u\n", retval);
		close(prog_fd);
		return 1;
	}

	memset(log_buf, 0, sizeof(log_buf));
	if (rejit_xdp_prog(prog_fd, prog_b, ARRAY_SIZE(prog_b),
			   log_buf, sizeof(log_buf)) < 0) {
		fprintf(stderr, "BPF_PROG_REJIT failed: %s\n%s\n",
			strerror(errno), log_buf);
		close(prog_fd);
		return 1;
	}

	if (test_run_xdp_prog(prog_fd, &retval) < 0) {
		fprintf(stderr, "BPF_PROG_TEST_RUN after rejit failed: %s\n",
			strerror(errno));
		close(prog_fd);
		return 1;
	}

	close(prog_fd);

	if (retval != XDP_DROP) {
		fprintf(stderr, "unexpected post-rejit retval %u\n", retval);
		return 1;
	}

	printf("same prog_fd re-jitted from XDP_PASS to XDP_DROP\n");
	return 0;
}
