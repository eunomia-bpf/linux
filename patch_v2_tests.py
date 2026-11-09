"""v2: selftests for JIT-inlined KF_FASTCALL kfuncs."""
import base64
import sys
from pathlib import Path

S = Path("/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2")
T = S / "tools/testing/selftests/bpf"
files = dict(arg.split("=", 1) for arg in sys.argv[1:])


def edit(path, pairs):
    s = path.read_text()
    for old, new in pairs:
        n = s.count(old)
        if n != 1:
            raise SystemExit(f"{path}: {n} matches for {old[:60]!r}")
        s = s.replace(old, new)
    path.write_text(s)
    print("edited", path.relative_to(S))


for rel, b64 in files.items():
    (T / rel).write_text(base64.b64decode(b64).decode())
    print("wrote", rel)

edit(T / "test_kmods/bpf_testmod.c", [
("""__bpf_kfunc u64 bpf_kfunc_call_test_pair_arg(u64 a, struct prog_test_pair_arg s, u64 b)
""",
"""/* KF_FASTCALL kfuncs for the JIT inlining tests: one the JIT can copy, one
 * with a branch that it cannot.
 */
__bpf_kfunc u64 bpf_kfunc_call_test_fastcall_lt(u64 a, u64 b)
{
	return a < b;
}

__bpf_kfunc u64 bpf_kfunc_call_test_fastcall_div(u64 a, u64 b)
{
	return b ? a / b : 0;
}

__bpf_kfunc u64 bpf_kfunc_call_test_pair_arg(u64 a, struct prog_test_pair_arg s, u64 b)
"""),
("""BTF_ID_FLAGS(func, bpf_kfunc_call_test_ret_fastcall, KF_FASTCALL)
""",
"""BTF_ID_FLAGS(func, bpf_kfunc_call_test_ret_fastcall, KF_FASTCALL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fastcall_lt, KF_FASTCALL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fastcall_div, KF_FASTCALL)
"""),
])

h = T / "test_kmods/bpf_testmod_kfunc.h"
s = h.read_text()
anchor = "#endif /* _BPF_TESTMOD_KFUNC_H */"
if s.count(anchor) != 1:
    raise SystemExit("bpf_testmod_kfunc.h: end guard not found")
h.write_text(s.replace(anchor,
"""__u64 bpf_kfunc_call_test_fastcall_lt(__u64 a, __u64 b) __ksym;
__u64 bpf_kfunc_call_test_fastcall_div(__u64 a, __u64 b) __ksym;

""" + anchor))
print("edited", h.relative_to(S))

edit(T / "prog_tests/verifier.c", [
("""#include "verifier_bpf_fastcall.skel.h"
""",
"""#include "verifier_bpf_fastcall.skel.h"
#include "verifier_kfunc_inline.skel.h"
"""),
("""void test_verifier_bpf_fastcall(void)         { RUN(verifier_bpf_fastcall); }
""",
"""void test_verifier_bpf_fastcall(void)         { RUN(verifier_bpf_fastcall); }
void test_verifier_kfunc_inline(void)         { RUN(verifier_kfunc_inline); }
"""),
])
