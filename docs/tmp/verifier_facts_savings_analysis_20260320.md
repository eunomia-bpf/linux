# Verifier Facts Savings Analysis (2026-03-20)

## Baseline

- Current tree baseline is:
  - `kernel/bpf/jit_validators.c`: 1990 LOC
  - `kernel/bpf/jit_directives.c`: 748 LOC
  - `kernel/bpf/verifier.c`: 26201 LOC
- The user-provided `2056` LOC number for `jit_validators.c` appears stale; all estimates below use the current tree's 1990-line file.

`jit_validators.c` is split roughly as follows:

| Section | LOC | Lines |
|---|---:|---|
| Common helpers before pattern framework | 199 | `10-208` |
| Generic pattern framework | 327 | `258-584` |
| `COND_SELECT` | 167 | `586-752` |
| `WIDE_MEM` | 191 | `755-945` |
| `ROTATE` | 170 | `947-1116` |
| `BITFIELD_EXTRACT` | 197 | `1119-1315` |
| `ADDR_CALC` | 43 | `1318-1360` |
| `ENDIAN_FUSION` | 131 | `1362-1492` |
| `BRANCH_FLIP` | 298 | `1498-1795` |
| Generic tail / dispatch / rule validation | 193 | `1798-1990` |

## Executive Summary

The important result is:

1. Saving verifier facts helps correctness and a few targeted checks.
2. It does **not** remove most of `jit_validators.c`, because most of that file is not reconstructing liveness/range/type; it is reconstructing **instruction shape** from bare xlated BPF.
3. A facts-only design saves **0 LOC** in `jit_validators.c` in a strict reading, about **66 LOC** in a practical reading with extra CFG-derived facts, and about **74 LOC** in the optimistic upper bound.
4. The code added to persist facts is larger than the validator code deleted. Best estimate: **about +360 LOC added** across verifier/header/free paths.
5. `jit_directives.c` barely changes from facts alone: **0 LOC** simplification attributable to verifier facts.
6. For the current seven forms, scheme C ("recompile-time 50-line liveness") is the best cost/benefit point. Scheme B only becomes attractive if the long-term plan is to persist much richer semantics or move canonical-form detection itself to load time.

My recommendation:

- Near term: choose **scheme C**.
- Medium term: only choose **scheme B** if BpfReJIT intends to add more semantics-sensitive rewrites and is willing to pay persistent memory for them.
- If the goal is to remove hundreds of validator lines, neither B nor C is enough. That requires a stronger design: precompute **canonical form descriptors** at load time, not just verifier facts.

## 1. What Verifier Facts Are Worth Saving

### 1.1 Facts already computed in `insn_aux_data`

Useful `insn_aux_data` fields today:

| Field | Source | Usefulness for rejit |
|---|---|---|
| `live_regs_before` | `include/linux/bpf_verifier.h:596-598`, computed at `kernel/bpf/verifier.c:25641-25724` | High |
| `scc` | `include/linux/bpf_verifier.h:592-597`, computed at `kernel/bpf/verifier.c:25735-25909` | Medium |
| `ptr_type` | `include/linux/bpf_verifier.h:525-529`, set via `save_aux_ptr_type()` at `kernel/bpf/verifier.c:20844-20880` | Medium |
| `map_index` / `map_off` | `include/linux/bpf_verifier.h:531-534`, set in verifier memory access checks | Low-medium |
| `ctx_field_size` | `include/linux/bpf_verifier.h:559` | Low-medium |
| `jmp_point` / `prune_point` / `force_checkpoint` / `calls_callback` | `include/linux/bpf_verifier.h:581-590` | Mostly CFG bookkeeping; limited direct rejit value |
| `needs_zext` / `zext_dst` / `nospec` / `nospec_result` | `include/linux/bpf_verifier.h:561-567` | Mostly verifier/JIT fixup metadata, not current form validation |

Low-value fields for this use case:

- `seen`
- `fastcall_pattern`
- `fastcall_spills_num`
- `arg_prog`
- `call_imm`
- most BTF/kptr/object fixup metadata

Observation:

- Persisting `insn_aux_data` as-is is **not enough**. It does not contain per-insn register type/range state, only a few specialized verifier side channels.

### 1.2 Facts only present in verifier state today

The full register facts live in `struct bpf_reg_state` (`include/linux/bpf_verifier.h:37-211`) inside `struct bpf_func_state` / `struct bpf_verifier_state` (`include/linux/bpf_verifier.h:274-322`, `362-435`):

- `type`
- `off`
- `var_off`
- `smin_value` / `smax_value`
- `umin_value` / `umax_value`
- `s32_min_value` / `s32_max_value`
- `u32_min_value` / `u32_max_value`
- `id`
- `ref_obj_id`
- `precise`

These are the only place where per-register type/range knowledge exists. They are path-sensitive and temporary.

Two constraints matter:

1. These are **not symbolic expression facts**.
   - They say "register 3 is scalar in range `[0, 31]`".
   - They do **not** say "register 3 equals `(r2 >> 8) & 0xff`".
   - That means they do not identify rotate / bitfield-extract / wide-load / select shapes.
2. They are **multi-state**.
   - A single instruction can be reached by several verifier states.
   - Rejit needs a joined fact lattice, not one raw verifier state.

### 1.3 Facts I would actually persist

For current BpfReJIT forms, the useful persistent subset is:

1. `live_regs_before`
2. `live_regs_after` (new; verifier computes `out` transiently today but does not store it)
3. `scc`
4. `calls_callback`
5. A small set of CFG facts:
   - `is_jump_target`
   - `predecessor_count` or small predecessor summary
   - `reachable`
6. Current-frame per-register joined facts:
   - `type`
   - `off`
   - `var_off`
   - `s32/u32 min/max`
   - optional `s64/u64 min/max`

I would **not** persist:

- stack state
- `precise`
- `prune_point`
- `force_checkpoint`
- `seen`
- `nospec` / `nospec_result`
- fastcall metadata

Reason:

- Current canonical forms are register- and CFG-local.
- Persisting full verifier stack state would dominate memory and still not eliminate structural matching.

## 2. Important Engineering Constraint: Final xlated insns do not match verifier-time indices

This is the main hidden cost in scheme B.

The verifier computes `scc` and `live_regs_before` before later rewriting passes:

- `compute_scc()` / `compute_live_registers()` run at `kernel/bpf/verifier.c:26046-26050`
- later passes then mutate instructions:
  - `convert_ctx_accesses()` at `26092-26095`
  - `do_misc_fixups()` at `26096-26097`
  - `opt_subreg_zext_lo32_rnd_hi32()` at `26102-26105`
  - `fixup_call_args()` at `26108-26109`

The verifier already has machinery like `adjust_insn_aux_data()` (`kernel/bpf/verifier.c:21926-21955`) and `orig_idx`, but that machinery is aimed at existing aux fields, not at a new permanent joined register-fact array.

Implication:

- A robust `bpf_rejit_aux` implementation must either:
  1. remap facts through later instruction rewrites, or
  2. materialize final facts after the rewrite pipeline, or
  3. accept that facts are only exact for original instructions and lossy for inserted ones.

This alone adds meaningful implementation cost.

## 3. Why Most Validator Code Does Not Go Away

Current validator complexity is dominated by **shape recognition**:

- matching exact opcode classes
- matching exact immediate placement
- matching temp-register choreography
- matching fixed jump layout
- normalizing instruction sequences into canonical params

Verifier facts do not encode those things.

Examples:

- `ROTATE` still needs to prove that two shifts plus OR are exactly a rotate shape; a scalar range does not tell you that.
- `BITFIELD_EXTRACT` still needs to prove shift/mask order and normalize `mask-first` vs `shift-first`.
- `WIDE_MEM` still needs to prove byte offsets are contiguous and endianness comes from the shift schedule.
- `BRANCH_FLIP` still needs to prove both bodies are locally re-emittable and fit x86 branch-distance constraints.

So scheme B does **not** turn 1990 lines into a small dispatcher. It only removes a few places where validator logic is compensating for missing semantic facts.

## 4. Per-form Simplification

### 4.1 `COND_SELECT` (`kernel/bpf/jit_validators.c:624-752`, 167 LOC)

What facts help:

- liveness can tell whether compare operands or destination remain live after the compare/update point
- type facts can say the compared values are scalar, but the emitter already assumes BPF-comparison legality

What still must remain:

- 2-insn guarded-update recognition
- 3-insn compact select recognition
- 4-insn diamond recognition
- canonical param extraction

Bottom line:

- Facts do not delete the parser.
- Current `dst`-alias rejection (`694-702`, `744-747`) is mostly an **emitter strategy** restriction, not a missing-verifier-facts restriction.

Estimated validator reduction:

- **0 LOC** in the strict design
- **up to 8 LOC** only if the emitter is also changed to exploit liveness-aware aliasing

### 4.2 `WIDE_MEM` (`755-945`, 191 LOC)

What facts help:

- base register type could be checked directly from saved reg facts
- liveness could be used for extra temp-register sanity checks

What still must remain:

- chunk parsing
- contiguous offset proof
- endian normalization
- canonical width/base extraction

Bottom line:

- Almost all of this section is structural matching.

Estimated validator reduction:

- **0 LOC**

### 4.3 `ROTATE` (`947-1116`, 170 LOC)

What facts help:

- almost nothing for current code

What still must remain:

- pattern family matching
- shift-order normalization
- masked-rotate mask check
- rotate amount derivation

Bottom line:

- Range/type facts do not express "this is a rotate".

Estimated validator reduction:

- **0 LOC**

### 4.4 `BITFIELD_EXTRACT` (`1119-1315`, 197 LOC)

What facts help:

- almost nothing for current code

What still must remain:

- 8 pattern variants
- mask/shift normalization
- canonical mask derivation

Bottom line:

- Verifier ranges are too weak to replace symbolic extract-shape recognition.

Estimated validator reduction:

- **0 LOC**

### 4.5 `ADDR_CALC` (`1318-1360`, 43 LOC)

What facts help:

- saved reg types can tell us whether the `ADD` is ptr + scalar

What still must remain:

- proving the site is exactly `mov; lsh; add`
- extracting `dst/base/index/scale`

Bottom line:

- A tiny semantic check becomes easier, but the section is already tiny.

Estimated validator reduction:

- **0 LOC** in practice

### 4.6 `ENDIAN_FUSION` (`1362-1492`, 131 LOC)

What facts help:

- this is the one clear win for liveness
- store fusion changes the post-site value of the source register unless the swapped value is dead after the store

New check that becomes possible:

- require store-source register to be dead after the `stx` site

This fixes the current correctness hole:

- original sequence:
  - `endian rX`
  - `stx [base+off], rX`
- fused sequence:
  - `movbe [base+off], rX`
- after fusion, `rX` keeps its old value; the original program leaves `rX` byteswapped

What still must remain:

- shape matching
- width derivation from load/store opcode
- canonical param extraction

Estimated validator reduction:

- **0 LOC deleted**
- **about +8 LOC** added for the liveness-based store check

### 4.7 `BRANCH_FLIP` (`1498-1795`, 298 LOC)

What facts help:

- almost nothing

What still must remain:

- branch/diamond shape parsing
- body linearizability proof
- x86 max-native-bytes budget
- body copying into canonical params

Bottom line:

- This section is dominated by backend-emission constraints, not missing verifier semantics.

Estimated validator reduction:

- **0 LOC**

## 5. Generic Helper Savings

There is only one clear generic win if scheme B also persists CFG-derived facts:

1. `bpf_jit_has_interior_edge()` (`kernel/bpf/jit_validators.c:158-208`, 51 LOC)
2. `bpf_jit_site_has_side_effects()` (`kernel/bpf/jit_validators.c:1806-1828`, 23 LOC)

If load-time facts include predecessor / jump-target summaries and a small per-insn side-effect classification, both helpers collapse to simple fact lookups.

Estimated validator reduction here:

- **74 LOC**

Without those extra CFG facts, even this saving disappears.

## 6. Total `jit_validators.c` Savings

### Strict scheme B

Definition:

- persist verifier facts only:
  - `live_regs_before/after`
  - `scc`
  - joined reg type/range facts
- do not redesign emitters
- do not add extra precomputed CFG/side-effect summaries beyond what verifier already exposes

Estimated `jit_validators.c` delta:

- deletions: **0 LOC**
- additions for endian store liveness check: **+8 LOC**
- net file size: **1998 LOC**

This version is correct but does **not** simplify the validator.

### Practical scheme B

Definition:

- strict scheme B plus small CFG-derived facts:
  - jump-target / predecessor summary
  - side-effect classification

Estimated `jit_validators.c` delta:

- delete `bpf_jit_has_interior_edge()`: **-51 LOC**
- delete `bpf_jit_site_has_side_effects()`: **-23 LOC**
- add endian store liveness guard: **+8 LOC**
- optimistic small cleanups elsewhere: **0 LOC**

Best estimate:

- net reduction: **-66 LOC**
- resulting file: **about 1924 LOC**

### Optimistic upper bound

If emitters are also adjusted to use saved liveness more aggressively, the upper bound is still modest:

- extra savings in `COND_SELECT`: **about 8 LOC**
- no meaningful extra savings elsewhere

Optimistic total:

- net reduction: **about -74 LOC**
- resulting file: **about 1916 LOC**

### Conclusion on validator savings

For the current seven forms, the believable saving is:

- **strict reading: 0 LOC**
- **practical reading: about 66 LOC**
- **optimistic upper bound: about 74 LOC**

This is the core answer: scheme B does **not** materially shrink `jit_validators.c`.

## 7. `jit_directives.c` Simplification

Facts alone do not simplify `jit_directives.c`.

Why:

- `jit_directives.c` is mostly:
  - rollback snapshotting
  - staged image management
  - ksym shadowing
  - commit/abort
  - policy swapping

Those concerns are independent of verifier facts.

Only one nearby issue exists:

- `bpf_jit_rule_release()` in `kernel/bpf/jit_directives.c:263-276` frees the heap-copied branch bodies for `BRANCH_FLIP`.

But that complexity is caused by the current `BRANCH_FLIP` canonical-param ABI, not by missing verifier facts. Since scheme B does not eliminate `BRANCH_FLIP` body copying, this code stays.

Estimated `jit_directives.c` reduction attributable to verifier facts:

- **0 LOC**

## 8. Code Added to Save Facts

### 8.1 Proposed structure

I would add a new immutable object owned by the main program aux:

```c
struct bpf_rejit_reg_fact {
	u32 type;
	s32 off;
	struct tnum var_off;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	/* Optional future fields:
	 * s64 smin_value, smax_value;
	 * u64 umin_value, umax_value;
	 */
};

struct bpf_rejit_insn_fact {
	u16 live_regs_before;
	u16 live_regs_after;
	u16 flags;      /* reachable / jump_target / side_effect_free / calls_callback */
	u16 reserved;
	u32 scc;
	struct bpf_rejit_reg_fact regs[MAX_BPF_REG];
};

struct bpf_rejit_aux {
	u32 len;
	u32 version;
	struct bpf_rejit_insn_fact insn[];
};
```

And in `struct bpf_prog_aux`:

```c
struct bpf_rejit_aux *rejit_aux;
```

### 8.2 Where it should hang

It should hang off `bpf_prog_main_aux(prog)`:

- main program owns it
- subprograms reference the main aux copy
- matches existing shared recompile state style (`main_prog_aux`)

### 8.3 Lifecycle

Allocate:

- after verifier success
- after final instruction rewrite/remap is complete

Use:

- read-only during all future `BPF_PROG_JIT_RECOMPILE` calls

Free:

- when the main `bpf_prog_aux` is freed

### 8.4 Join policy

Because facts are path-sensitive in verifier state, the persistent snapshot must be a safe join:

- `type`: exact if all reaching states agree, otherwise degrade
- `var_off`: `tnum_union`
- integer bounds: loosen to enclosing interval
- speculative states: ignore for rejit facts

This makes the facts safe but sometimes imprecise.

## 9. Memory Cost

### 9.1 What not to do

Do **not** store raw `struct bpf_reg_state` per instruction.

Measured on this tree's `vmlinux` BTF:

- `struct bpf_reg_state`: **112 bytes**
- `struct bpf_insn_aux_data`: **96 bytes**

With `MAX_BPF_REG = 11`, a raw per-insn snapshot would cost:

- `11 * 112 = 1232 bytes` of regs per insn
- around **1240 bytes / insn** with a tiny header

Examples:

| Program len | Raw full snapshot |
|---|---:|
| 1000 insns | 1.24 MB |
| 4096 insns | 5.08 MB |
| 10000 insns | 12.4 MB |
| 32768 insns | 40.6 MB |

That is too expensive for a permanent always-on aux object.

### 9.2 Reasonable compact design

The compact structure above is about **456 bytes / insn** if we keep:

- type
- off
- `var_off`
- `s32/u32` bounds
- `live_before/after`
- flags
- `scc`

Examples:

| Program len | Compact snapshot |
|---|---:|
| 1000 insns | 456 KB |
| 4096 insns | 1.87 MB |
| 10000 insns | 4.56 MB |
| 32768 insns | 14.9 MB |

If full 64-bit min/max ranges are retained as well, the cost rises to about **808 bytes / insn**:

| Program len | Compact + full64 ranges |
|---|---:|
| 1000 insns | 808 KB |
| 4096 insns | 3.31 MB |
| 10000 insns | 8.08 MB |
| 32768 insns | 26.5 MB |

Conclusion:

- full raw `bpf_reg_state` snapshots are not viable
- compact joined facts are viable for small/medium programs, but still non-trivial

## 10. Estimated Code Added for Scheme B

Best-effort engineering estimate for the compact design above:

| Area | Added LOC |
|---|---:|
| new struct definitions / flags / accessors | 90 |
| `bpf_prog_aux` hook + free path | 20 |
| capture/join helpers in verifier | 170 |
| final materialization / remap after rewrite passes | 80 |
| small plumbing call sites | 20 |
| **Total** | **360** |

This is the right scale:

- not 50 lines
- not 1000 lines
- roughly **360 LOC**

## 11. Net Code Delta

Using the practical scheme B estimate:

- facts persistence added: **+360 LOC**
- `jit_validators.c` reduced: **-66 LOC**
- `jit_directives.c` reduced: **0 LOC**

Net delta:

- **+294 LOC**

Using the optimistic upper bound:

- facts persistence added: **+360 LOC**
- `jit_validators.c` reduced: **-74 LOC**
- `jit_directives.c` reduced: **0 LOC**

Net delta:

- **+286 LOC**

So scheme B is a **net code increase**, not a code reduction, for the current validator set.

## 12. Scheme Comparison

### Scheme A: current design

- Recompile sees only bare xlated BPF
- `jit_validators.c` does structural + semantic recovery itself
- validator size: **1990 LOC**
- persistent memory: **0**

Pros:

- no load-time memory tax
- no verifier coupling

Cons:

- cannot do precise liveness-dependent safety checks
- manual conservative pattern logic remains large

### Scheme B: persist verifier facts

- validator can read liveness / types / ranges / CFG summaries
- persistent memory: **about 456 B/insn** for a compact design
- added code: **about 360 LOC**
- validator shrink: **about 66 LOC** practical, **74 LOC** optimistic

Pros:

- enables precise safety checks like endian-store liveness
- gives a reusable semantic substrate for future rewrites

Cons:

- net code increase
- non-trivial permanent memory overhead
- awkward alignment with post-verifier instruction rewrites
- still leaves almost all structural matching intact

### Scheme C: recompile-time 50-line liveness

- run a tiny local liveness pass over final xlated insns during recompile
- no persistent memory
- added code: **about 50 LOC**

What it buys immediately:

- fixes the endian-store bug cleanly
- can support a few liveness-aware checks without touching verifier lifetime

What it does not buy:

- type/range facts
- any big validator shrink

Pros:

- smallest implementation
- aligned to final post-fixup xlated insns
- no `bpf_prog_aux` memory cost

Cons:

- no reusable type/range substrate

## 13. Recommendation

For the current BpfReJIT form set, the best choice is:

1. **Choose scheme C now.**
   - It solves the one clear correctness gap (`ENDIAN_FUSION` store case).
   - It has the lowest implementation cost.
   - It naturally runs on the final xlated program, so there is no remap problem.

2. **Do not choose scheme B just to shrink `jit_validators.c`.**
   - The shrink is too small.
   - The added verifier/plumbing/memory cost is larger than the code removed.

3. **Choose scheme B only if the real goal is broader than code shrink.**
   - Example: future semantics-sensitive rewrites that genuinely need joined reg types/ranges.
   - Example: a long-term plan to build a persistent semantic DB for rejit.

4. **If the actual goal is to remove hundreds of validator lines, use a stronger design than B.**
   - Move canonical-form recognition itself to load time.
   - Persist canonical descriptors, not just verifier facts.
   - That is the design that can collapse the 327-line pattern framework and most form-specific matchers.

## Final Answer

If you only save verifier facts (`liveness`, type/range, `scc`, branch/side-effect summaries), `jit_validators.c` does **not** collapse. The realistic saving is only about **66 LOC** in the current 1990-line file, while fact persistence itself costs about **360 LOC** and a permanent memory overhead of about **456 bytes per instruction** for a compact design.

So:

- scheme B is **not** a code-size win for the current forms
- scheme C is the best near-term choice
- scheme B only makes sense as an infrastructure investment for future rewrites, not as a way to delete today's validator code
