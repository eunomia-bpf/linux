#!/bin/bash
# checkpatch fixes as fixups, autosquash, then author = Yusheng Zheng.
set -e
D=/workspaces/.agent-state/bpf-benchmark-supervisor; S=$D/kfunc-copy-v2
BASE=f25f6319e248
cd $S
git checkout -q kfunc-copy-v2
export GIT_AUTHOR_NAME="Yusheng Zheng" GIT_AUTHOR_EMAIL=yunwei356@gmail.com
export GIT_COMMITTER_NAME="Yusheng Zheng" GIT_COMMITTER_EMAIL=yunwei356@gmail.com
python3 - <<'EOP'
from pathlib import Path
def edit(path, old, new):
    p = Path(path); s = p.read_text()
    assert s.count(old) == 1, (path, old[:60])
    p.write_text(s.replace(old, new)); print("edited", path)
edit("kernel/bpf/verifier.c", """		env->insn_aux_data[insn_idx].fastcall_spilled_regs = spilled_regs;
	} else
		subprog->keep_fastcall_stack = 1;
""", """		env->insn_aux_data[insn_idx].fastcall_spilled_regs = spilled_regs;
	} else {
		subprog->keep_fastcall_stack = 1;
	}
""")
edit("arch/x86/net/bpf_jit_comp.c", """				if (fm->ret_flags & BTF_FMODEL_JIT_INLINE) {
					err = emit_kfunc_inline(&prog, (unsigned long)func, fm,
								bpf_fastcall_spilled_regs(env, bpf_prog, i - 1));
""", """				if (fm->ret_flags & BTF_FMODEL_JIT_INLINE) {
					u32 live = bpf_fastcall_spilled_regs(env, bpf_prog, i - 1);

					err = emit_kfunc_inline(&prog, (unsigned long)func, fm,
								live);
""")
edit("arch/arm64/net/bpf_jit_comp.c", """			if (fm->ret_flags & BTF_FMODEL_JIT_INLINE) {
				ret = emit_kfunc_inline(ctx, func_addr, fm,
							bpf_fastcall_spilled_regs(env, ctx->prog, i));
""", """			if (fm->ret_flags & BTF_FMODEL_JIT_INLINE) {
				u32 live = bpf_fastcall_spilled_regs(env, ctx->prog, i);

				ret = emit_kfunc_inline(ctx, func_addr, fm, live);
""")
EOP
git commit -q -m "fixup! bpf: Let JITs inline KF_FASTCALL kfuncs" kernel/bpf/verifier.c
git commit -q -m "fixup! bpf, x86: Inline KF_FASTCALL kfuncs by copying them" arch/x86/net/bpf_jit_comp.c
git commit -q -m "fixup! bpf, arm64: Inline KF_FASTCALL kfuncs by copying them" arch/arm64/net/bpf_jit_comp.c
GIT_SEQUENCE_EDITOR=: git rebase -q -i --autosquash $BASE
git rebase -q --exec "git commit -q --amend --no-edit --reset-author" $BASE
git log --format="%h %an <%ae> | %s" $BASE..HEAD | cat
git status --short | head
