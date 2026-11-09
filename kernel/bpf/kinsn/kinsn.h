/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_KINSN_H
#define _BPF_KINSN_H

#include <linux/bpf.h>

int kinsn_emit_rol64(const struct bpf_kinsn_operands *ops, u8 *buf);
int kinsn_emit_select64(const struct bpf_kinsn_operands *ops, u8 *buf);
int kinsn_emit_select_lt64(const struct bpf_kinsn_operands *ops, u8 *buf);
int kinsn_emit_extract64(const struct bpf_kinsn_operands *ops, u8 *buf);
int kinsn_emit_load_be64(const struct bpf_kinsn_operands *ops, u8 *buf);
int kinsn_emit_lea64(const struct bpf_kinsn_operands *ops, u8 *buf);

/* the native code of an operation, if this architecture has it */
#define KINSN_EMIT(op)	(IS_ENABLED(CONFIG_X86_64) ? kinsn_emit_##op : NULL)

#endif /* _BPF_KINSN_H */
