/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf

#if !defined(_TRACE_BPF_RECOMPILE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_RECOMPILE_H

#include <linux/tracepoint.h>

TRACE_EVENT(bpf_jit_recompile_start,

	TP_PROTO(u32 prog_id, u32 num_rules),

	TP_ARGS(prog_id, num_rules),

	TP_STRUCT__entry(
		__field(u32, prog_id)
		__field(u32, num_rules)
	),

	TP_fast_assign(
		__entry->prog_id = prog_id;
		__entry->num_rules = num_rules;
	),

	TP_printk("prog_id=%u num_rules=%u",
		  __entry->prog_id, __entry->num_rules)
);

TRACE_EVENT(bpf_jit_recompile_end,

	TP_PROTO(u32 prog_id, u32 num_applied, u64 duration_ns, bool success),

	TP_ARGS(prog_id, num_applied, duration_ns, success),

	TP_STRUCT__entry(
		__field(u32, prog_id)
		__field(u32, num_applied)
		__field(u64, duration_ns)
		__field(bool, success)
	),

	TP_fast_assign(
		__entry->prog_id = prog_id;
		__entry->num_applied = num_applied;
		__entry->duration_ns = duration_ns;
		__entry->success = success;
	),

	TP_printk("prog_id=%u num_applied=%u duration_ns=%llu success=%d",
		  __entry->prog_id, __entry->num_applied,
		  __entry->duration_ns, __entry->success)
);

TRACE_EVENT(bpf_jit_recompile_rule,

	TP_PROTO(u32 prog_id, u32 site_insn, u16 family, u16 native_choice,
		 bool applied),

	TP_ARGS(prog_id, site_insn, family, native_choice, applied),

	TP_STRUCT__entry(
		__field(u32, prog_id)
		__field(u32, site_insn)
		__field(u16, family)
		__field(u16, native_choice)
		__field(bool, applied)
	),

	TP_fast_assign(
		__entry->prog_id = prog_id;
		__entry->site_insn = site_insn;
		__entry->family = family;
		__entry->native_choice = native_choice;
		__entry->applied = applied;
	),

	TP_printk("prog_id=%u site_insn=%u family=%u native_choice=%u applied=%d",
		  __entry->prog_id, __entry->site_insn, __entry->family,
		  __entry->native_choice, __entry->applied)
);

#endif

#include <trace/define_trace.h>
