Reviewed `5006b75b7fa9` against `4169c9c90532`. I found two x86 instruction-copying defects, selftest robustness problems, and unresolved questions about mutable kernel text. The verifier bookkeeping generally looks sound.

No files were modified. Validation used source inspection and small compiler/assembler examples written to stdout; no kernel builds or runtime reproductions were run.

1. **BUG — Copied x86 memory instructions lose their exception-table fixups.**

   **Location:** [arch/x86/net/bpf_jit_comp.c:2729](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/x86/net/bpf_jit_comp.c:2729), copying at line 2741.

   **Scenario:** Register a `KF_FASTCALL` kfunc with an ignored pointer argument and a nofault load:

   ```c
   __bpf_kfunc u64 read_value(const u64 *p__ign)
   {
           u64 value;

           __get_kernel_nofault(&value, p__ign, u64, fault);
           return value;
   fault:
           return 0;
   }
   ```

   With asm-goto outputs, its successful path can be just:

   ```asm
   movq (%rdi), %rax
   ret
   ```

   The fault path is reached through `__ex_table`, without a branch instruction in the successful path. The scanner accepts the load and copies it, but the exception-table entry still names the original kernel instruction. Passing an unmapped address then faults at a JIT address without the intended fixup, instead of returning zero.

   I confirmed this code shape with Clang 18 using an equivalent exception-table asm-goto example. The new arithmetic kfuncs do not trigger it, but it affects otherwise valid future users of the flag.

   **Suggested fix:** Reject instructions covered by `search_exception_tables()`. Alternatively, initially restrict actual memory accesses while retaining register operations and LEA. Supporting copied exception entries requires additional relocation and validation.

2. **BUG — The x86 return test mistakes XOP instructions for `ret`.**

   **Location:** [arch/x86/net/bpf_jit_comp.c:2725](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/x86/net/bpf_jit_comp.c:2725).

   **Scenario:** The decoder stores an XOP instruction’s opcode separately from its XOP prefix. These valid encodings have opcode byte `0xc3`:

   ```text
   8f e8 78 c3 c8 03    vprotq $3, %xmm0, %xmm1
   8f e9 78 c3 c8       vphaddbq %xmm0, %xmm1
   ```

   The loop recognizes `RET_INSN_OPCODE` before reaching `kfunc_insn_regs()` and its XOP rejection. It therefore accepts the preceding prefix of the function as the complete body, dropping this instruction and everything following it.

   This requires unusual kfunc text; ordinary kernel C compilation should not generate XOP. Nevertheless, an unsupported encoding must cause fallback, rather than successful truncation. LLVM’s assembler and the tree’s XOP tables confirm the encodings.

   **Suggested fix:** Reject VEX/XOP/EVEX and unsupported prefix forms before examining terminators, and require the appropriate legacy opcode form for both `ret` and the return-thunk jump.

3. **BUG — Inline-only selftest expectations fail when instrumentation correctly prevents copying.**

   **Location:** [tools/testing/selftests/bpf/progs/kfunc_inline_jit.c:17](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/tools/testing/selftests/bpf/progs/kfunc_inline_jit.c:17), also line 158.

   **Scenario:** Build with `CONFIG_KCOV=y` and `CONFIG_KCOV_INSTRUMENT_ALL=y`. Neither `helpers.o` nor the relevant test functions exclude coverage instrumentation. A rotate function then contains a coverage call and register-saving prologue. Both JITs correctly decline to copy it.

   The test nevertheless requires removed spills, fixed translated instruction numbers, and an inline rotate. It fails despite correct fallback behavior. Clang 18 with `-fsanitize-coverage=trace-pc` produced precisely this non-copyable shape.

   **Suggested fix:** Keep functional comparison tests applicable to fallback configurations. Use controlled test kfunc bodies for mandatory inline assertions, or explicitly gate those assertions on supported instrumentation configurations. Architecture restrictions alone are insufficient.

4. **BUG — The new test does not skip when `bpf_testmod` is unavailable.**

   **Location:** [tools/testing/selftests/bpf/prog_tests/kfunc_inline.c:59](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/tools/testing/selftests/bpf/prog_tests/kfunc_inline.c:59).

   **Scenario:** If loading `bpf_testmod.ko` fails, the runner sets `env.has_testmod = false` and announces that dependent tests will be skipped. This test proceeds to load objects requiring its kfuncs, producing failures during symbol resolution.

   **Suggested fix:** Check `env.has_testmod`, call `test__skip()`, and return before running either group. Existing module-dependent tests provide examples.

5. **QUESTION — Copying deliberately bypasses livepatch redirection, including patches already active at load time.**

   **Locations:** [arch/x86/net/bpf_jit_comp.c:2715](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/x86/net/bpf_jit_comp.c:2715), [arch/arm64/net/bpf_jit_comp.c:1522](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/arm64/net/bpf_jit_comp.c:1522).

   **Scenario:** Livepatch redirects an eligible kfunc through its ftrace entry to a corrected implementation. The copier skips that entry and copies the original body. A BPF program loaded **after** patch activation therefore still executes the old implementation. Copies loaded beforehand also remain unchanged.

   This differs from ordinary tracing visibility: livepatch can change functional behavior. The redirection occurs through `ftrace_regs_set_instruction_pointer()` in `kernel/livepatch/patch.c:121`.

   **Suggested fix:** Define and enforce the lifetime contract. Either exclude copy-eligible functions from livepatch, or integrate copies with patching/invalidation. Checking only whether a patch is currently active would not address later patch activation. Document the tracing consequences too.

6. **QUESTION — Eligibility is permanent, but the validated instruction body is not retained.**

   **Locations:** [kernel/bpf/verifier.c:3174](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/kernel/bpf/verifier.c:3174), [arch/x86/net/bpf_jit_comp.c:2720](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/x86/net/bpf_jit_comp.c:2720), [arch/arm64/net/bpf_jit_comp.c:1519](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/arm64/net/bpf_jit_comp.c:1519).

   **Scenario:** The eligibility probe succeeds, then a kprobe is installed in the body before actual JIT compilation. The later scan encounters INT3/BRK and fails. Because the inline flag is already set, neither backend falls back to a preserving call: program loading fails.

   Thus the documentation’s “where it cannot be copied, it is called” does not cover this transition. The x86 buffer stabilizes decoding versus copying within one invocation; it does not stabilize the verifier probe and subsequent JIT passes.

   **Suggested fix:** Cache a validated body and register-use description once, with suitable text-patching synchronization, and reuse it throughout compilation. Alternatively, explicitly define load failure as the policy and implement a safe fallback if transparent loading is required.

   Normal ftrace attachment changes only the skipped site, so it should not change copied lengths. x86 also checks final instruction boundaries against the preceding pass. I did **not** reproduce an accepted-body mutation causing cross-pass corruption; arm64’s final size check occurs after emission, so immutable input would provide a stronger guarantee.

7. **NIT — x86 SIB addressing without a base invents an RBP dependency.**

   **Location:** [arch/x86/net/bpf_jit_comp.c:2668](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/x86/net/bpf_jit_comp.c:2668).

   **Scenario:** GCC 13 compiles `return x * 8;` as:

   ```asm
   leaq 0(,%rdi,8), %rax
   ret
   ```

   For `mod=00` and SIB base field 5, there is no base register. The code nevertheless adds RBP to `used`, causing rejection. This is safe fallback, but misses a particularly simple intended optimization.

   **Suggested fix:** Handle the SIB no-base encoding explicitly before adding the base-register bit.

8. **NIT — The arm64 carry mask also matches FlagM instructions and invents operands.**

   **Location:** [arch/arm64/net/bpf_jit_comp.c:1459](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/arch/arm64/net/bpf_jit_comp.c:1459).

   **Scenario:** `rmif x0, #56, #0` encodes as `0xba1c0400` and matches the “add/sub with carry” mask. Its immediate bits are interpreted as `Rm = 28`, so the copier rejects it as using the arena register. Its actual GPR input is only x0.

   `setf8 w0` also matches this mask and acquires a fictitious x13 dependency. These examples cause conservative rejection or register accounting, rather than demonstrated corruption.

   **Suggested fix:** Match ADC/SBC forms more precisely, then explicitly support or reject RMIF/SETF. Keep encoding tests for these neighboring classes.

9. **NIT — The documentation omits the void-return exception and conditions on spill removal.**

   **Location:** [Documentation/bpf/kfuncs.rst:539](/workspaces/.agent-state/bpf-benchmark-supervisor/kfunc-copy-v2/Documentation/bpf/kfuncs.rst:539).

   **Scenario:** For a void fastcall kfunc, R0 can survive the call and have a spill/fill pair. The text describes R0 as clobbered and discusses preservation only for R1–R5. It also implies that inlining always removes spills, although stack-contract validation can disable removal.

   **Suggested fix:** State that R0 is clobbered for non-void functions, and qualify spill removal by successful pattern and stack-contract validation.

Things checked that appear fine:

- **Descriptor timing and identity:** `add_kfuncs()` precedes the existing summary consumers and pattern marking. Lookups include the original offset; module BTF handling retains module references.
- **Existing flags and stack accounting:** The two verifier-inlined casts retain their behavior. `bpf_kfunc_call_test_ret_fastcall()` returns more than eight bytes and remains rejected before eligibility probing. Non-inlined patterns retain their spills and `keep_fastcall_stack` prevents incorrect depth reduction.
- **Auxiliary indices:** Subprogram starts, extra passes, NOP removal, and successful constant blinding preserve the relevant metadata. The six-bit mask covers R0–R5.
- **Execution fallback:** Kfunc calls require JIT execution; failure does not expose removed spills to the interpreter. Both copiers preserve R0 for void functions independently of the `env == NULL` mask.
- **Register preservation and bounds:** x86 saves R9 and reverses pop order; emitted size fits the buffer. arm64 spare allocation excludes copied operands and fails before emitting if exhausted. Stack-argument state is invalidated at calls; AX temporaries do not span these calls.
- **Other decoder cases:** REX extensions, high-byte registers, RIP-relative rejection, SLS padding, return thunks, arm64 SP/ZR handling, conditional-compare immediates, and multiply-high Ra handling look sound for the audited forms. CSSC/CRC/PAC exclusions cause fallback. The random arithmetic comparison is deterministic and its reference operations avoid undefined shifts.