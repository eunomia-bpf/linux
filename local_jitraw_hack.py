"""LOCAL arm64 run only, never part of the series: without LLVM, print the raw
JIT image of programs with __jited checks instead of skipping them."""
import sys
from pathlib import Path
p = Path(sys.argv[1]) / "tools/testing/selftests/bpf/test_loader.c"
s = p.read_text()
old = r"""		if (err == -EOPNOTSUPP) {
			printf("%s:SKIP: jited programs disassembly is not supported,\n", __func__);
			printf("%s:SKIP: tests are built w/o LLVM development libs\n", __func__);
			test__skip();
			goto tobj_cleanup;
		}
"""
new = r"""		if (err == -EOPNOTSUPP) {
			struct bpf_prog_info info = {};
			__u32 ilen = sizeof(info), n;
			unsigned char *image;

			if (!bpf_prog_get_info_by_fd(bpf_program__fd(tprog), &info, &ilen) &&
			    (image = calloc(1, info.jited_prog_len))) {
				n = info.jited_prog_len;
				memset(&info, 0, sizeof(info));
				info.jited_prog_len = n;
				info.jited_prog_insns = (__u64)(unsigned long)image;
				ilen = sizeof(info);
				if (!bpf_prog_get_info_by_fd(bpf_program__fd(tprog), &info, &ilen)) {
					printf("JITRAW %s ", spec->prog_name);
					for (i = 0; i < n; i++)
						printf("%02x", image[i]);
					printf("\n");
				}
				free(image);
			}
			goto jit_done;
		}
"""
assert s.count(old) == 1
s = s.replace(old, new)
old2 = """		validate_msgs(tester->log_buf, &subspec->jited, emit_jited);
	}

	if (should_do_test_run(spec, subspec)) {"""
assert s.count(old2) == 1
s = s.replace(old2, """		validate_msgs(tester->log_buf, &subspec->jited, emit_jited);
	}
jit_done:

	if (should_do_test_run(spec, subspec)) {""")
p.write_text(s)
print("hacked", p)
