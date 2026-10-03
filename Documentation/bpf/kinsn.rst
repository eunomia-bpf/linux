.. SPDX-License-Identifier: GPL-2.0

====================================
Verified inline kernel instructions
====================================

A kinsn is a registered kfunc whose call can be emitted as native instructions
by a BPF JIT. The descriptor supplies a BPF proof sequence for verification
and an architecture-specific emitter for execution. Kinsns are kernel-owned;
BPF programs cannot register descriptors or provide native instructions.

Descriptor registration
=======================

Register the kfunc in a ``btf_kfunc_id_set`` and provide parallel arrays of
``kinsn_ids`` and ``kinsn_descs``, with ``kinsn_cnt`` entries. Each ID must be
in the set and must have no ``KF_*`` flags. The arrays bind descriptors to
explicit BTF IDs, independent of the order of the sorted kfunc set. The
ordinary kfunc allow filter still applies. A descriptor has these fields:

``owner``
  The owning module, or ``NULL`` for a built-in descriptor.

``max_insn_cnt`` and ``instantiate_insn``
  Bound and construct the BPF instruction sequence used as the proof. The
  callback receives the sidecar payload and returns the instruction count or
  a negative error for an invalid payload.

``max_emit_bytes`` and ``emit_x86`` / ``emit_arm64``
  Bound and emit the native instruction sequence. An emitter returns its byte
  count on x86-64 or instruction count on arm64, or a negative error. The JIT
  rejects an emitter that exceeds its declared bound.

Sidecar encoding
================

A kinsn call must be immediately preceded by a ``BPF_ALU64 | BPF_MOV | BPF_K``
instruction with ``src_reg = BPF_PSEUDO_KINSN_SIDECAR``. This instruction is
metadata and does not write a BPF register. It carries a 52-bit payload:

.. code-block:: text

   payload[3:0]   = dst_reg
   payload[19:4]  = off (as unsigned 16 bits)
   payload[51:20] = imm (as unsigned 32 bits)

The sidecar and the following ``BPF_PSEUDO_KFUNC_CALL`` form one operation.
An orphan sidecar, a call without its sidecar, or a sidecar before an ordinary
kfunc call is rejected. This use of ``MOV`` assigns meaning to a previously
reserved ``src_reg`` value; it is subject to review alongside the standardized
BPF instruction set.

Verification and JIT requirements
=================================

The verifier replaces each pair with its proof sequence, checks the resulting
program, then restores the pairs for JIT compilation. Proofs cannot contain
calls, exits, sidecars, pseudo ``ldimm64``, ``may_goto``, or ``gotox``. Jumps
must go forward and stay within the proof region or target its end. The
verifier records callee-saved registers used by proofs so that the JIT also
preserves them when compiling the restored program.

A kinsn program requires a GPL-compatible license and a JIT that advertises
``bpf_jit_supports_kinsn()``. The default implementation returns false;
x86-64 and arm64 provide native emitters and override it. The selected
descriptor must provide an emitter for the running architecture. A kinsn
program is rejected when these conditions are not met.

Trust model
===========

Verification proves safety of the BPF proof sequence. It does not establish
equivalence between the proof and native machine instructions. The descriptor
owner must ensure that every accepted payload emits native instructions with
the same observable behavior and respects the BPF calling convention, memory
access rules, and the emitter's size bound. Reviewers should assess that
equivalence for each descriptor and architecture.
