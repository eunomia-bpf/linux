/*
 * analyze_xlated.c - Load a BPF program and dump its xlated instructions
 * focusing on jumps to detect interior edges in cmov patterns.
 *
 * Build: gcc -O2 -o analyze_xlated analyze_xlated.c -lbpf
 * Run: sudo ./analyze_xlated <prog.bpf.o>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_INSNS 65536

/* BPF instruction encoding */
struct bpf_insn_raw {
	uint8_t code;
	uint8_t regs;  /* dst:4, src:4 */
	int16_t off;
	int32_t imm;
};

static const char *cls_name(uint8_t code) {
	switch (code & 0x07) {
	case 0x00: return "LD";
	case 0x01: return "LDX";
	case 0x02: return "ST";
	case 0x03: return "STX";
	case 0x04: return "ALU";
	case 0x05: return "JMP";
	case 0x06: return "JMP32";
	case 0x07: return "ALU64";
	default: return "???";
	}
}

static int is_cond_jump(uint8_t code) {
	uint8_t cls = code & 0x07;
	uint8_t op = code >> 4;
	if (cls != 0x05 && cls != 0x06) return 0;
	/* Exclude JA (0x0), EXIT (0x9), CALL (0x8) */
	if (op == 0x0 || op == 0x8 || op == 0x9) return 0;
	return 1;
}

static int is_ja(uint8_t code) {
	uint8_t cls = code & 0x07;
	uint8_t op = code >> 4;
	return (cls == 0x05 && op == 0x0);
}

static int is_simple_mov(const struct bpf_insn_raw *insn) {
	uint8_t cls = insn->code & 0x07;
	uint8_t op = insn->code >> 4;
	uint8_t src = (insn->code >> 3) & 0x01;
	if (cls != 0x04 && cls != 0x07) return 0;
	if (op != 0x0b) return 0; /* BPF_MOV */
	if (insn->off != 0) return 0;
	if (src == 0 /* BPF_K */) return insn->regs >> 4 == 0; /* src_reg==0 */
	else return insn->imm == 0; /* BPF_X */
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <prog.bpf.o>\n", argv[0]);
		return 1;
	}

	struct bpf_object *obj = bpf_object__open(argv[1]);
	if (!obj) {
		fprintf(stderr, "bpf_object__open failed: %s\n", strerror(errno));
		return 1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		int fd = bpf_program__fd(prog);
		if (fd < 0) continue;

		/* Get xlated program length */
		struct bpf_prog_info info = {};
		uint32_t info_len = sizeof(info);
		if (bpf_obj_get_info_by_fd(fd, &info, &info_len)) {
			fprintf(stderr, "bpf_obj_get_info_by_fd failed\n");
			continue;
		}

		uint32_t insn_cnt = info.xlated_prog_len / sizeof(struct bpf_insn_raw);
		if (insn_cnt == 0 || insn_cnt > MAX_INSNS) {
			fprintf(stderr, "Program has %u insns, skipping\n", insn_cnt);
			continue;
		}

		struct bpf_insn_raw *insns = calloc(insn_cnt, sizeof(*insns));
		if (!insns) continue;

		info.xlated_prog_insns = (__u64)(uintptr_t)insns;
		/* Need a fresh info struct with xlated_prog_len set */
		struct bpf_prog_info info2 = {};
		info2.xlated_prog_len = insn_cnt * sizeof(*insns);
		info2.xlated_prog_insns = (__u64)(uintptr_t)insns;
		uint32_t info2_len = sizeof(info2);
		if (bpf_obj_get_info_by_fd(fd, &info2, &info2_len)) {
			fprintf(stderr, "bpf_obj_get_info_by_fd (2) failed: %s\n", strerror(errno));
			free(insns);
			continue;
		}

		printf("\n=== Program: %s (%u insns) ===\n", bpf_program__name(prog), insn_cnt);

		/* Find cmov compact sites */
		printf("\n--- Compact sites (mov, jcc+1, mov) ---\n");
		for (uint32_t i = 1; i+1 < insn_cnt; i++) {
			if (is_simple_mov(&insns[i-1]) &&
			    is_cond_jump(insns[i].code) && insns[i].off == 1 &&
			    is_simple_mov(&insns[i+1]) &&
			    (insns[i-1].regs & 0x0F) == (insns[i+1].regs & 0x0F))
			{
				uint32_t site_start = i - 1;
				uint32_t site_len = 3;
				uint32_t site_end = site_start + site_len;
				printf("  Compact site at [%u..%u]: ", site_start, site_end-1);

				/* Check for interior edges */
				int has_interior = 0;
				for (uint32_t j = 0; j < insn_cnt; j++) {
					uint8_t code = insns[j].code;
					uint8_t cls = code & 0x07;
					uint8_t op = code >> 4;
					int32_t target;

					if (cls != 0x05 && cls != 0x06) continue;
					if (op == 0x8 || op == 0x9) continue; /* CALL, EXIT */

					if (is_ja(code)) {
						if (cls == 0x05)
							target = (int32_t)j + 1 + insns[j].off;
						else
							target = (int32_t)j + 1 + insns[j].imm;
					} else {
						target = (int32_t)j + 1 + insns[j].off;
					}

					if (target < 0 || (uint32_t)target >= insn_cnt) continue;

					if ((j < site_start || j >= site_end) &&
					    (uint32_t)target > site_start && (uint32_t)target < site_end) {
						printf("INTERIOR EDGE from [%u] -> [%d]\n", j, target);
						has_interior = 1;
					}
				}
				if (!has_interior)
					printf("clean (no interior edges)\n");
			}
		}

		/* Find cmov diamond sites */
		printf("\n--- Diamond sites (jcc+2, mov, ja+1, mov) ---\n");
		for (uint32_t i = 0; i+3 < insn_cnt; i++) {
			if (is_cond_jump(insns[i].code) && insns[i].off == 2 &&
			    is_simple_mov(&insns[i+1]) &&
			    is_ja(insns[i+2].code) && insns[i+2].off == 1 &&
			    is_simple_mov(&insns[i+3]) &&
			    (insns[i+1].regs & 0x0F) == (insns[i+3].regs & 0x0F))
			{
				uint32_t site_start = i;
				uint32_t site_len = 4;
				uint32_t site_end = site_start + site_len;
				printf("  Diamond site at [%u..%u]: ", site_start, site_end-1);

				int has_interior = 0;
				for (uint32_t j = 0; j < insn_cnt; j++) {
					uint8_t code = insns[j].code;
					uint8_t cls = code & 0x07;
					uint8_t op = code >> 4;
					int32_t target;

					if (cls != 0x05 && cls != 0x06) continue;
					if (op == 0x8 || op == 0x9) continue;

					if (is_ja(code)) {
						if (cls == 0x05)
							target = (int32_t)j + 1 + insns[j].off;
						else
							target = (int32_t)j + 1 + insns[j].imm;
					} else {
						target = (int32_t)j + 1 + insns[j].off;
					}

					if (target < 0 || (uint32_t)target >= insn_cnt) continue;

					if ((j < site_start || j >= site_end) &&
					    (uint32_t)target > site_start && (uint32_t)target < site_end) {
						printf("INTERIOR EDGE from [%u] -> [%d]\n", j, target);
						has_interior = 1;
					}
				}
				if (!has_interior)
					printf("clean (no interior edges)\n");
			}
		}

		/* Print all jumps for context */
		printf("\n--- All jump instructions ---\n");
		for (uint32_t i = 0; i < insn_cnt; i++) {
			uint8_t code = insns[i].code;
			uint8_t cls = code & 0x07;
			uint8_t op = code >> 4;
			int32_t target;

			if (cls != 0x05 && cls != 0x06) continue;
			if (op == 0x8 || op == 0x9) continue; /* skip CALL, EXIT */

			if (is_ja(code)) {
				if (cls == 0x05)
					target = (int32_t)i + 1 + insns[i].off;
				else
					target = (int32_t)i + 1 + insns[i].imm;
				printf("  [%3u] JA    -> %d\n", i, target);
			} else {
				target = (int32_t)i + 1 + insns[i].off;
				printf("  [%3u] JCC code=0x%02x dst=%u src=%u -> %d\n",
				       i, code, insns[i].regs & 0xF, insns[i].regs >> 4, target);
			}
		}

		free(insns);
	}

	bpf_object__close(obj);
	return 0;
}
