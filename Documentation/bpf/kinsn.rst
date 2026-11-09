.. SPDX-License-Identifier: GPL-2.0

======
kinsns
======

A kinsn is a kfunc that BPF programs use like an instruction, such as a
rotate or a conditional select. The verifier checks each call as a short
sequence of BPF instructions that compute the kfunc, and the JIT puts native
instructions in place of the call.

Programs call a kinsn like any other kfunc. Arguments whose names end in
``__k`` must be known constants. ``CONFIG_BPF_KINSN`` provides kinsns for
rotate, conditional select, bit field extract, big-endian load, prefetch,
16-byte copy and address computation.

Verification
============

The verifier replaces each kinsn call with its BPF instructions before it
analyzes the program, so it knows as much about the result as if the program
had computed it with BPF instructions. The instructions get the arguments in
R1-R5 and leave the result in R0, and the analysis treats their entry and
exits like those of the call: only the arguments are readable at the entry,
and R1-R5 are not readable after it.

After the analysis, a kinsn call that the JIT has native code for goes back
into the program, with its operands bound to the registers that the moves
around the call copied them from or to. Otherwise the instructions stay, so a
kinsn runs on every JIT. They also stay when the verifier rewrites them later,
for example with speculation barriers, when they access memory other than the
stack, map values, memory and packets, and when constant blinding is on.

Native code
===========

The ``emit`` callback of a kinsn writes its native code for the bound
registers and the values of the constant arguments, for example ``rol $13``
or ``movbe 8(%rdi)``. Without ``emit``, or when it has no code for the CPU,
the JIT copies the code that the compiler produced for the kfunc and renames
its registers to the bound ones. It copies only straight-line moves, ALU
instructions and address computations on the registers of a call, without
division or rip-relative addressing. A copy cannot use the constants as
immediates or put the result in the register of an argument, so it suits
kfuncs that compile to the instruction itself, such as a prefetch.

Native code is trusted like the rest of the JIT: it has to compute what the
BPF instructions compute, with the same memory accesses.

Defining kinsns
===============

A kfunc set registers kinsns for some of its kfuncs::

        static const struct bpf_insn rol64_insns[] = { ... };

        static const struct bpf_kinsn kinsns[] = {
                { &kinsn_ids[0], rol64_insns, ARRAY_SIZE(rol64_insns), rol64_emit },
        };

        static const struct btf_kfunc_id_set kinsn_set = {
                .set       = &kinsn_kfunc_ids,
                .kinsns    = kinsns,
                .kinsn_cnt = ARRAY_SIZE(kinsns),
        };

Registration checks the instructions: they may use R0-R5, ALU instructions,
loads and stores, and forward jumps that land within them, so that they end by
falling through the last one, but not the sign extension, signed division and
byte swap of cpu v4, which not every JIT has. Each argument and the result must fit in one register, and the kfunc may
have no kfunc flags. ``emit`` writes at most ``BPF_KINSN_MAX_EMIT`` bytes.
