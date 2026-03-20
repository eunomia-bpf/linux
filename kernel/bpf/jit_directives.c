// SPDX-License-Identifier: GPL-2.0-only
/* BPF JIT recompile orchestration */
#include <linux/bpf.h>
#include <linux/bpf_jit_directives.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#define BPF_JIT_RECOMPILE_LOG_MAX_SIZE SZ_64K

struct bpf_jit_recompile_prog_state {
	struct bpf_prog *prog;
	bpf_func_t bpf_func;
	void __percpu *priv_stack_ptr;
	struct exception_table_entry *extable;
	void *jit_data;
	struct bpf_insn *insnsi_copy;
	u32 insn_cnt;
	u32 jited_len;
	u32 num_exentries;
	u32 fp_start;
	u32 fp_end;
	bool jited;
	bool exception_boundary;
};

struct bpf_jit_recompile_rollback_state {
	struct bpf_prog_aux *main_aux;
	u64 (*bpf_exception_cb)(u64 cookie, u64 sp, u64 bp, u64, u64);
	struct bpf_jit_recompile_prog_state *prog_states;
	u32 prog_state_cnt;
};

void bpf_jit_recompile_prog_log(const struct bpf_prog *prog, const char *fmt, ...)
{
	struct bpf_verifier_log *log;
	va_list args;

	if (!prog || !prog->aux)
		return;

	log = bpf_prog_main_aux(prog)->jit_recompile_log;
	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

void bpf_jit_recompile_rule_log(const struct bpf_prog *prog,
				const struct bpf_jit_rule *rule,
				const char *fmt, ...)
{
	struct bpf_verifier_log *log;
	u32 site_end = 0;
	va_list args;

	if (!prog || !prog->aux || !rule)
		return;

	log = bpf_prog_main_aux(prog)->jit_recompile_log;
	if (!bpf_verifier_log_needed(log))
		return;

	if (!check_add_overflow(rule->site_start,
				rule->site_len ? rule->site_len - 1 : 0,
				&site_end)) {
		bpf_log(log, "rule %u: form %u site %u-%u: ",
			rule->user_index, rule->canonical_form,
			rule->site_start, site_end);
	} else {
		bpf_log(log, "rule %u: form %u site %u: ",
			rule->user_index, rule->canonical_form,
			rule->site_start);
	}

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
	bpf_log(log, "\n");
}

static void
bpf_jit_recompile_save_prog_state(struct bpf_jit_recompile_prog_state *state,
				  struct bpf_prog *prog)
{
	state->prog = prog;
	state->bpf_func = prog->bpf_func;
	state->priv_stack_ptr = prog->aux->priv_stack_ptr;
	state->extable = prog->aux->extable;
	state->jit_data = prog->aux->jit_data;
	state->jited_len = prog->jited_len;
	state->num_exentries = prog->aux->num_exentries;
	state->fp_start = prog->aux->ksym.fp_start;
	state->fp_end = prog->aux->ksym.fp_end;
	state->jited = prog->jited;
	state->exception_boundary = prog->aux->exception_boundary;
	state->insn_cnt = prog->len;
	state->insnsi_copy = kmemdup(prog->insnsi,
				     array_size(prog->len,
						sizeof(*prog->insnsi)),
				     GFP_KERNEL_ACCOUNT);
}

static void
bpf_jit_recompile_snapshot_free(struct bpf_jit_recompile_rollback_state *state)
{
	u32 i;

	if (!state->prog_states)
		goto out_reset;

	for (i = 0; i < state->prog_state_cnt; i++)
		kfree(state->prog_states[i].insnsi_copy);
	kfree(state->prog_states);
out_reset:
	state->prog_states = NULL;
	state->prog_state_cnt = 0;
	state->main_aux = NULL;
}

static void
bpf_jit_recompile_restore_prog_state(const struct bpf_jit_recompile_prog_state *state)
{
	struct bpf_prog *prog = state->prog;

	if (prog->aux->jit_data && prog->aux->jit_data != state->jit_data)
		bpf_jit_recompile_abort(prog);

	if (state->insnsi_copy)
		memcpy(prog->insnsi, state->insnsi_copy,
		       array_size(state->insn_cnt, sizeof(*prog->insnsi)));

	prog->aux->priv_stack_ptr = state->priv_stack_ptr;
	prog->aux->extable = state->extable;
	prog->aux->jit_data = state->jit_data;
	prog->jited_len = state->jited_len;
	prog->aux->num_exentries = state->num_exentries;
	prog->aux->ksym.fp_start = state->fp_start;
	prog->aux->ksym.fp_end = state->fp_end;
	prog->jited = state->jited;
	prog->aux->exception_boundary = state->exception_boundary;
	smp_store_release(&prog->bpf_func, state->bpf_func);
	bpf_jit_recompile_reset_prog_aux(prog);
}

static int
bpf_jit_recompile_snapshot(struct bpf_prog *prog,
			   struct bpf_jit_recompile_rollback_state *state)
{
	struct bpf_prog_aux *main_aux = bpf_prog_main_aux(prog);
	u32 real_func_cnt = main_aux->real_func_cnt ? : main_aux->func_cnt;
	u32 cnt = 1;
	u32 i = 0;

	if (main_aux->func_cnt && main_aux->func)
		cnt += real_func_cnt;

	state->prog_states = kcalloc(cnt, sizeof(*state->prog_states),
				      GFP_KERNEL_ACCOUNT);
	if (!state->prog_states)
		return -ENOMEM;

	state->main_aux = main_aux;
	state->bpf_exception_cb = main_aux->bpf_exception_cb;
	state->prog_state_cnt = cnt;
	bpf_jit_recompile_save_prog_state(&state->prog_states[i++], prog);
	if (!state->prog_states[0].insnsi_copy)
		goto err_restore;

	if (!(main_aux->func_cnt && main_aux->func))
		return 0;

	for (; i < cnt; i++) {
		if (!main_aux->func[i - 1])
			goto err_restore;
		bpf_jit_recompile_save_prog_state(&state->prog_states[i],
						  main_aux->func[i - 1]);
		if (!state->prog_states[i].insnsi_copy)
			goto err_restore;
	}

	return 0;

err_restore:
	state->prog_state_cnt = i;
	bpf_jit_recompile_snapshot_free(state);
	return -ENOMEM;
}

static void
bpf_jit_recompile_restore(struct bpf_jit_recompile_rollback_state *state)
{
	u32 i;

	if (!state->prog_states)
		return;

	for (i = 0; i < state->prog_state_cnt; i++)
		bpf_jit_recompile_restore_prog_state(&state->prog_states[i]);

	if (state->main_aux)
		smp_store_release(&state->main_aux->bpf_exception_cb,
				  state->bpf_exception_cb);
}

static bool
bpf_jit_recompile_stage_ok(const struct bpf_prog *prog,
			   bpf_func_t old_bpf_func,
			   bool final_pass)
{
	if (!prog->jited || !prog->bpf_func)
		return false;
	if (prog->bpf_func != old_bpf_func)
		return false;
	if (!bpf_jit_recompile_staged_func(prog))
		return false;
	if (final_pass && !bpf_jit_recompile_has_staged_image(prog))
		return false;
	if (bpf_jit_recompile_staged_num_exentries(prog) &&
	    !bpf_jit_recompile_staged_extable(prog))
		return false;

	return true;
}

static void
bpf_jit_recompile_shadow_ksym_add(struct bpf_prog *prog,
				  bpf_func_t new_bpf_func, u32 new_len,
				  struct exception_table_entry *extable,
				  u32 num_exentries,
				  u32 fp_start, u32 fp_end)
{
	struct bpf_ksym *shadow = &prog->aux->jit_recompile_ksym;

	if (!prog->aux->ksym.prog || !new_bpf_func || !new_len)
		return;

	memset(shadow, 0, sizeof(*shadow));
	INIT_LIST_HEAD_RCU(&shadow->lnode);
	shadow->start = (unsigned long)new_bpf_func;
	shadow->end = (unsigned long)new_bpf_func + new_len;
	strscpy(shadow->name, prog->aux->ksym.name, KSYM_NAME_LEN);
	shadow->prog = prog->aux->ksym.prog;
	shadow->owner = prog;
	shadow->extable = extable;
	shadow->num_exentries = num_exentries;
	shadow->fp_start = fp_start;
	shadow->fp_end = fp_end;
	bpf_ksym_add(shadow);
}

static void bpf_jit_recompile_shadow_ksym_del(struct bpf_prog *prog)
{
	if (!list_empty(&prog->aux->jit_recompile_ksym.lnode))
		bpf_ksym_del(&prog->aux->jit_recompile_ksym);
}

void bpf_jit_rule_release(struct bpf_jit_rule *rule)
{
	if (!rule)
		return;

	if (rule->canonical_form == BPF_JIT_CF_BRANCH_FLIP) {
		kfree((void *)(long)
		      rule->params.params[BPF_JIT_BFLIP_PARAM_BODY_A_PTR].value);
		kfree((void *)(long)
		      rule->params.params[BPF_JIT_BFLIP_PARAM_BODY_B_PTR].value);
	}

	memset(&rule->params, 0, sizeof(rule->params));
}

static bool bpf_pseudo_call_insn(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}

static bool bpf_jit_recompile_has_trampoline_dependency(
	const struct bpf_prog *prog)
{
	return prog && prog->aux &&
	       prog->type == BPF_PROG_TYPE_STRUCT_OPS &&
	       rcu_access_pointer(prog->aux->st_ops_assoc);
}

static struct bpf_prog *
bpf_jit_recompile_image_prog(struct bpf_prog_aux *main_aux,
			     struct bpf_prog *prog, u32 image_idx)
{
	return main_aux->func_cnt && main_aux->func ?
		main_aux->func[image_idx] : prog;
}

static struct bpf_prog *
bpf_jit_recompile_ksym_prog(struct bpf_prog_aux *main_aux,
			    struct bpf_prog *prog, u32 real_func_cnt,
			    u32 image_idx)
{
	if (!(main_aux->func_cnt && main_aux->func) || !image_idx)
		return prog;

	return image_idx < real_func_cnt ? main_aux->func[image_idx] : NULL;
}

static int bpf_jit_recompile_prog_images(
	struct bpf_prog *prog)
{
	struct bpf_prog_aux *main_aux = bpf_prog_main_aux(prog);
	struct bpf_binary_header **old_headers = NULL;
	void __percpu **old_priv_stacks = NULL;
	bpf_func_t old_prog_func = READ_ONCE(prog->bpf_func);
	u64 (*new_exception_cb)(u64 cookie, u64 sp, u64 bp, u64, u64);
	u32 image_cnt = 1;
	u32 real_func_cnt = 0;
	u32 i;
	int err = 0;
	bool keep_old_images = false;

	if (main_aux->func_cnt && main_aux->func) {
		real_func_cnt = main_aux->real_func_cnt ?: main_aux->func_cnt;
		image_cnt = real_func_cnt;
	}

	old_headers = kcalloc(image_cnt, sizeof(*old_headers), GFP_KERNEL_ACCOUNT);
	old_priv_stacks = kcalloc(image_cnt, sizeof(*old_priv_stacks),
				  GFP_KERNEL_ACCOUNT);
	if (!old_headers || !old_priv_stacks) {
		err = -ENOMEM;
		goto out_free;
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);

		if (!image_prog) {
			err = -EINVAL;
			goto out_abort;
		}
		bpf_jit_recompile_reset_prog_aux(image_prog);
		image_prog->aux->jit_recompile_active = true;
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);
		bpf_func_t old_bpf_func = READ_ONCE(image_prog->bpf_func);
		struct bpf_prog *recompiled;

		recompiled = bpf_int_jit_compile(image_prog);
		if (recompiled != image_prog ||
		    !bpf_jit_recompile_stage_ok(image_prog, old_bpf_func, false)) {
			err = -EIO;
			goto out_abort;
		}
	}

	if (main_aux->func_cnt && main_aux->func) {
		for (i = 0; i < real_func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];
			struct bpf_insn *insn;
			u32 j;

			if (!func) {
				err = -EINVAL;
				goto out_abort;
			}

			insn = func->insnsi;
			for (j = 0; j < func->len; j++, insn++) {
				int subprog;
				bpf_func_t target;

				if (bpf_pseudo_func(insn)) {
					subprog = insn->off;
					if (subprog < 0 || subprog >= real_func_cnt) {
						err = -EINVAL;
						goto out_abort;
					}
					target = bpf_jit_recompile_staged_func(main_aux->func[subprog]) ?:
						READ_ONCE(main_aux->func[subprog]->bpf_func);
					if (!target) {
						err = -EIO;
						goto out_abort;
					}
					insn[0].imm = (u32)(long)target;
					insn[1].imm = ((u64)(long)target) >> 32;
					continue;
				}
				if (!bpf_pseudo_call_insn(insn))
					continue;

				subprog = insn->off;
				if (subprog < 0 || subprog >= real_func_cnt) {
					err = -EINVAL;
					goto out_abort;
				}
				target = bpf_jit_recompile_staged_func(main_aux->func[subprog]) ?:
					READ_ONCE(main_aux->func[subprog]->bpf_func);
				if (!target) {
					err = -EIO;
					goto out_abort;
				}
				insn->imm = BPF_CALL_IMM(target);
			}
		}

		for (i = 0; i < image_cnt; i++) {
			struct bpf_prog *image_prog =
				bpf_jit_recompile_image_prog(main_aux, prog, i);
			bpf_func_t old_bpf_func = READ_ONCE(image_prog->bpf_func);
			struct bpf_prog *recompiled;

			recompiled = bpf_int_jit_compile(image_prog);
			if (recompiled != image_prog ||
			    !bpf_jit_recompile_stage_ok(image_prog, old_bpf_func, true)) {
				err = -EIO;
				goto out_abort;
			}
		}
	}

	/*
	 * When a policy is present but no rule was actually applied, keep the
	 * existing live image. Replacing it with a freshly allocated equivalent
	 * body would perturb relocation-sensitive bytes (for example helper call
	 * displacements) even though the effective lowering did not change.
	 */
	if (main_aux->jit_policy && !main_aux->jit_recompile_num_applied)
		goto out_no_commit;

	new_exception_cb = main_aux->bpf_exception_cb;
	if (main_aux->func_cnt && main_aux->func) {
		for (i = 0; i < real_func_cnt; i++) {
			struct bpf_prog *func = main_aux->func[i];

			if (func && func->aux->exception_cb) {
				new_exception_cb = (void *)(bpf_jit_recompile_staged_func(func) ?:
						READ_ONCE(func->bpf_func));
				break;
			}
		}
	} else if (prog->aux->exception_cb) {
		new_exception_cb = (void *)(bpf_jit_recompile_staged_func(prog) ?:
				 READ_ONCE(prog->bpf_func));
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);
		struct bpf_prog *ksym_prog =
			bpf_jit_recompile_ksym_prog(main_aux, prog,
						     real_func_cnt, i);

		if (image_prog->jited && image_prog->bpf_func)
			old_headers[i] = bpf_jit_binary_pack_hdr(image_prog);
		if (image_prog->aux->priv_stack_ptr !=
		    image_prog->aux->jit_recompile_priv_stack_ptr)
			old_priv_stacks[i] = image_prog->aux->priv_stack_ptr;

		if (!ksym_prog)
			continue;

		bpf_jit_recompile_shadow_ksym_add(
			ksym_prog, bpf_jit_recompile_staged_func(image_prog) ?:
				READ_ONCE(image_prog->bpf_func),
			bpf_jit_recompile_staged_len(image_prog),
			bpf_jit_recompile_staged_extable(image_prog),
			bpf_jit_recompile_staged_num_exentries(image_prog),
			bpf_jit_recompile_staged_fp_start(image_prog),
			bpf_jit_recompile_staged_fp_end(image_prog));
	}

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);

		err = bpf_jit_recompile_commit(image_prog);
		if (err)
			goto out_abort;
	}

	if (main_aux->func_cnt && main_aux->func) {
		prog->jited = 1;
		prog->jited_len = main_aux->func[0]->jited_len;
		prog->aux->extable = main_aux->func[0]->aux->extable;
		prog->aux->num_exentries = main_aux->func[0]->aux->num_exentries;
		prog->aux->exception_boundary =
			main_aux->func[0]->aux->exception_boundary;
		prog->aux->ksym.fp_start = main_aux->func[0]->aux->ksym.fp_start;
		prog->aux->ksym.fp_end = main_aux->func[0]->aux->ksym.fp_end;
		smp_store_release(&prog->bpf_func, main_aux->func[0]->bpf_func);
	}
		if (new_exception_cb)
			smp_store_release(&main_aux->bpf_exception_cb, new_exception_cb);

		err = bpf_prog_regenerate_trampolines(prog, old_prog_func);
		if (err) {
			bpf_jit_recompile_prog_log(
				prog,
				"warning: trampoline regeneration failed (err=%d); keeping old JIT text resident\n",
				err);
			pr_warn_ratelimited(
				"bpf jit recompile: prog id %u trampoline regeneration failed (err=%d); keeping old JIT text resident\n",
				prog->aux->id, err);
			keep_old_images = true;
			err = 0;
		}

		synchronize_rcu();
		/*
		 * Trampoline regeneration failure can leave old trampoline text
		 * transiently calling into the previous JIT image.
		 */
		if (keep_old_images)
			synchronize_rcu();

	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);
		struct bpf_prog *ksym_prog =
			bpf_jit_recompile_ksym_prog(main_aux, prog,
						     real_func_cnt, i);

		if (ksym_prog)
			bpf_prog_kallsyms_replace(
				ksym_prog, &ksym_prog->aux->jit_recompile_ksym,
				(unsigned long)READ_ONCE(ksym_prog->bpf_func),
				ksym_prog->jited_len, ksym_prog->aux->extable,
				ksym_prog->aux->num_exentries,
				ksym_prog->aux->ksym.fp_start,
				ksym_prog->aux->ksym.fp_end);

		if (old_headers[i] &&
		    old_headers[i] != bpf_jit_binary_pack_hdr(image_prog))
			bpf_jit_binary_pack_free(old_headers[i], NULL);
		if (old_priv_stacks[i])
			free_percpu(old_priv_stacks[i]);

		image_prog->aux->jit_recompile_active = false;
	}
	goto out_free;

out_no_commit:
	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);

		if (!image_prog)
			continue;
		bpf_jit_recompile_abort(image_prog);
		image_prog->aux->jit_recompile_active = false;
	}

out_free:
	kfree(old_priv_stacks);
	kfree(old_headers);
	return err;

out_abort:
	for (i = 0; i < image_cnt; i++) {
		struct bpf_prog *image_prog =
			bpf_jit_recompile_image_prog(main_aux, prog, i);
		struct bpf_prog *ksym_prog =
			bpf_jit_recompile_ksym_prog(main_aux, prog,
						     real_func_cnt, i);

		if (ksym_prog)
			bpf_jit_recompile_shadow_ksym_del(ksym_prog);
		if (image_prog) {
			bpf_jit_recompile_abort(image_prog);
			image_prog->aux->jit_recompile_active = false;
		}
	}
	goto out_free;
}

int bpf_prog_jit_recompile(union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct bpf_prog_aux *main_aux = NULL;
	struct bpf_jit_policy *policy = NULL;
	struct bpf_jit_policy *old_policy = NULL;
	struct bpf_verifier_log log = {};
	struct bpf_jit_recompile_rollback_state rollback = {};
	bool locked = false;
	bool stock_rejit;
	u32 log_level = 0;
	u32 log_size_actual = 0;
	int log_err = 0;
	int err = 0;

	if (attr->jit_recompile.flags)
		return -EINVAL;

	if (!bpf_jit_supports_recompile())
		return -EOPNOTSUPP;

	stock_rejit = attr->jit_recompile.policy_fd == 0;

	if (!capable(CAP_BPF) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	prog = bpf_prog_get(attr->jit_recompile.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	main_aux = bpf_prog_main_aux(prog);
	if (!mutex_trylock(&main_aux->jit_recompile_mutex)) {
		err = -EBUSY;
		goto out_put;
	}
	locked = true;

	if (attr->jit_recompile.log_level &&
	    attr->jit_recompile.log_buf &&
	    attr->jit_recompile.log_size) {
		log_level = BPF_LOG_LEVEL1 | BPF_LOG_FIXED;
	}

	err = bpf_vlog_init(&log, log_level,
			    log_level ?
			    u64_to_user_ptr(attr->jit_recompile.log_buf) : NULL,
			    log_level ?
			    min_t(u32, attr->jit_recompile.log_size,
				  BPF_JIT_RECOMPILE_LOG_MAX_SIZE) : 0);
	if (err)
		goto out_put;
	main_aux->jit_recompile_log = &log;

	/* Must be a JITed program */
	if (!prog->jited) {
		bpf_jit_recompile_prog_log(prog, "program is not JITed\n");
		err = -EINVAL;
		goto out_put;
	}

	if (bpf_jit_recompile_has_trampoline_dependency(prog)) {
		bpf_jit_recompile_prog_log(
			prog,
			"live struct_ops programs are not supported: trampoline regeneration does not cover struct_ops yet\n");
		err = -EOPNOTSUPP;
		goto out_put;
	}

	/* Don't support blinded programs in POC */
	if (prog->blinded) {
		bpf_jit_recompile_prog_log(prog,
					   "blinded programs are not supported\n");
		err = -EOPNOTSUPP;
		goto out_put;
	}

	if (!stock_rejit) {
		/* Parse and validate policy blob */
		policy = bpf_jit_parse_policy(prog, attr->jit_recompile.policy_fd);
		if (IS_ERR(policy)) {
			err = PTR_ERR(policy);
			policy = NULL;
			goto out_put;
		}

		if (policy->active_cnt == 0) {
			bpf_jit_recompile_prog_log(prog,
						   "policy has no active rules\n");
			bpf_jit_free_policy(policy);
			policy = NULL;
			err = -EINVAL;
			goto out_put;
		}
	}

	err = bpf_jit_recompile_snapshot(prog, &rollback);
	if (err) {
		bpf_jit_recompile_prog_log(prog,
					   "failed to save rollback state: err=%d\n",
					   err);
		goto out_put;
	}

	/* Stock re-JIT (clear policy) */
	if (stock_rejit) {
		old_policy = main_aux->jit_policy;
		main_aux->jit_policy = NULL;
		goto do_recompile;
	}

	/* Swap policy on prog */
	old_policy = main_aux->jit_policy;
	main_aux->jit_policy = policy;
	policy = NULL;

do_recompile:
	main_aux->jit_recompile_num_applied = 0;

	/* Trigger re-JIT for the active func[] images. */
	err = bpf_jit_recompile_prog_images(prog);
	if (err) {
		struct bpf_jit_policy *failed_policy = NULL;

		bpf_jit_recompile_prog_log(prog,
					   "re-JIT failed with err=%d\n", err);
		bpf_jit_recompile_restore(&rollback);
		failed_policy = main_aux->jit_policy;
		main_aux->jit_policy = old_policy;
		old_policy = NULL;
		if (failed_policy != main_aux->jit_policy)
			bpf_jit_free_policy(failed_policy);
		bpf_jit_recompile_prog_log(
			prog,
			"restored the pre-recompile image and policy\n");
		goto out_put;
	}

	if (old_policy) {
		bpf_jit_free_policy(old_policy);
		old_policy = NULL;
	}
	if (!stock_rejit && !main_aux->jit_recompile_num_applied) {
		bpf_jit_recompile_restore(&rollback);
		bpf_jit_recompile_prog_log(
			prog,
			"no rules applied; kept the pre-recompile image\n");
	}

out_put:
	main_aux->jit_recompile_num_applied = 0;
	if (main_aux)
		main_aux->jit_recompile_log = NULL;
	if (locked)
		mutex_unlock(&main_aux->jit_recompile_mutex);
	log_err = bpf_vlog_finalize(&log, &log_size_actual);
	if (log_err == -ENOSPC)
		log_err = 0;
	if (!err && log_err)
		err = log_err;
	bpf_jit_recompile_snapshot_free(&rollback);
	bpf_jit_free_policy(policy);
	bpf_jit_free_policy(old_policy);
	bpf_prog_put(prog);
	return err;
}
