#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/argv.h>
#include <faux/list.h>
#include <faux/error.h>
#include <faux/file.h>
#include <klish/khelper.h>
#include <klish/kplugin.h>
#include <klish/kentry.h>
#include <klish/kscheme.h>
#include <klish/kcontext.h>
#include <klish/kpargv.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>
#include <sysrepo/netconf_acm.h>

#include "klish_plugin_sysrepo.h"

#define ERRORMSG "Error: "

#define ARG_PATH "path"
#define ARG_FROM_PATH "from_path"
#define ARG_TO_PATH "to_path"


// Print sysrepo session errors
static void srp_print_errors(sr_session_ctx_t *session)
{
	const sr_error_info_t *err_info = NULL;
	int rc = 0;
	unsigned int i = 0;

	if (!session)
		return;

	rc = sr_session_get_error(session, &err_info);
	if ((rc != SR_ERR_OK) || !err_info)
		return;
	// Show the first error only. Because probably next errors are
	// originated from internal sysrepo code but is not from subscribers.
//	for (i = 0; i < err_info->err_count; i++)
	for (i = 0; i < (err_info->err_count < 1 ? err_info->err_count : 1); i++)
		fprintf(stderr, ERRORMSG "%s\n", err_info->err[i].message);
}


// Print sysrepo session errors and then specified error
static void srp_error(sr_session_ctx_t *session, const char *fmt, ...)
{
	srp_print_errors(session);

	if (fmt) {
		va_list argptr;
		va_start(argptr, fmt);
		vfprintf(stderr, fmt, argptr);
		va_end(argptr);
	}
}


static faux_argv_t *param2argv(const faux_argv_t *cur_path,
	const kpargv_t *pargv, const char *entry_name)
{
	faux_list_node_t *iter = NULL;
	faux_list_t *pargs = NULL;
	faux_argv_t *args = NULL;
	kparg_t *parg = NULL;

	assert(pargv);
	if (!pargv)
		return NULL;

	pargs = kpargv_find_multi(pargv, entry_name);
	if (cur_path)
		args = faux_argv_dup(cur_path);
	else
		args = faux_argv_new();

	iter = faux_list_head(pargs);
	while ((parg = (kparg_t *)faux_list_each(&iter))) {
		faux_argv_add(args, kparg_value(parg));
	}
	faux_list_free(pargs);

	return args;
}


// Candidate from pargv contains possible begin of current word (that must be
// completed). kpargv's list don't contain candidate but only already parsed
// words.
static int srp_compl_or_help(kcontext_t *context, bool_t help,
	pt_e enabled_ptypes, bool_t use_cur_path, bool_t existing_nodes_only)
{
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	const char *entry_name = NULL;
	faux_argv_t *cur_path = NULL;

	assert(context);

	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	if (use_cur_path)
		cur_path = (faux_argv_t *)srp_udata_path(context);
	entry_name = kentry_name(kcontext_candidate_entry(context));
	args = param2argv(cur_path, kcontext_parent_pargv(context), entry_name);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);
	pline_print_completions(pline, help, enabled_ptypes, existing_nodes_only);
	pline_free(pline);

	return 0;
}


int srp_compl(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_ALL, BOOL_TRUE, BOOL_FALSE);
}


int srp_help(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_ALL, BOOL_TRUE, BOOL_FALSE);
}


int srp_compl_set(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_SET, BOOL_TRUE, BOOL_FALSE);
}


int srp_help_set(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_SET, BOOL_TRUE, BOOL_FALSE);
}


int srp_compl_del(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_DEL, BOOL_TRUE, BOOL_TRUE);
}


int srp_help_del(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_DEL, BOOL_TRUE, BOOL_TRUE);
}


int srp_compl_edit(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_EDIT, BOOL_TRUE, BOOL_FALSE);
}


int srp_compl_edit_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_EDIT, BOOL_FALSE, BOOL_FALSE);
}


int srp_help_edit(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_EDIT, BOOL_TRUE, BOOL_FALSE);
}


int srp_help_edit_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_EDIT, BOOL_FALSE, BOOL_FALSE);
}


int srp_compl_insert(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_INSERT, BOOL_TRUE, BOOL_TRUE);
}


int srp_help_insert(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_INSERT, BOOL_TRUE, BOOL_TRUE);
}


int srp_compl_show(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_SHOW, BOOL_TRUE, BOOL_TRUE);
}


int srp_compl_show_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_SHOW, BOOL_FALSE, BOOL_TRUE);
}


int srp_help_show(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_SHOW, BOOL_TRUE, BOOL_TRUE);
}


int srp_help_show_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_SHOW, BOOL_FALSE, BOOL_TRUE);
}


int srp_prompt_edit_path(kcontext_t *context)
{
	faux_argv_t *cur_path = NULL;
	char *path = NULL;

	assert(context);

	cur_path = (faux_argv_t *)srp_udata_path(context);
	if (cur_path)
		path = faux_argv_line(cur_path);
	kcontext_printf(context, "[edit%s%s]\n",
		path ? " " : "", path ? path : "");
	faux_str_free(path);

	return 0;
}


static int srp_check_type(kcontext_t *context,
	pt_e not_accepted_nodes, size_t max_expr_num, bool_t use_cur_path)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	const char *entry_name = NULL;
	const char *value = NULL;
	pexpr_t *expr = NULL;
	size_t expr_num = 0;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	if (use_cur_path)
		cur_path = (faux_argv_t *)srp_udata_path(context);
	entry_name = kentry_name(kcontext_candidate_entry(context));
	value = kcontext_candidate_value(context);
	args = param2argv(cur_path, kcontext_parent_pargv(context), entry_name);
	if (value)
		faux_argv_add(args, value);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid)
		goto err;
	expr_num = faux_list_len(pline->exprs);
	if (expr_num < 1)
		goto err;
	if ((max_expr_num > 0) &&  // '0' means unlimited
		(expr_num > max_expr_num))
		goto err;
	expr = pline_current_expr(pline);
	if (expr->pat & not_accepted_nodes)
		goto err;

	ret = 0;
err:
	pline_free(pline);

	return ret;
}


int srp_PLINE_SET(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_SET, 0, BOOL_TRUE);
}


int srp_PLINE_DEL(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_DEL, 1, BOOL_TRUE);
}


int srp_PLINE_EDIT(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_EDIT, 1, BOOL_TRUE);
}


int srp_PLINE_EDIT_ABS(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_EDIT, 1, BOOL_FALSE);
}


int srp_PLINE_INSERT_FROM(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_INSERT, 1, BOOL_TRUE);
}


int srp_PLINE_SHOW(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_SHOW, 1, BOOL_TRUE);
}


int srp_PLINE_SHOW_ABS(kcontext_t *context)
{
	return srp_check_type(context, PT_NOT_SHOW, 1, BOOL_FALSE);
}


static faux_argv_t *assemble_insert_to(sr_session_ctx_t *sess, const kpargv_t *pargv,
	faux_argv_t *cur_path, const char *candidate_value, pline_opts_t *opts)
{
	faux_argv_t *args = NULL;
	faux_argv_t *insert_to = NULL;
	pline_t *pline = NULL;
	pexpr_t *expr = NULL;
	size_t i = 0;

	assert(sess);

	args = param2argv(cur_path, pargv, ARG_FROM_PATH);
	pline = pline_parse(sess, args, opts);
	expr = pline_current_expr(pline);
	for (i = 0; i < (expr->args_num - expr->list_pos); i++) {
		faux_argv_node_t *iter = faux_argv_iterr(args);
		faux_argv_del(args, iter);
	}
	insert_to = param2argv(args, pargv, ARG_TO_PATH);
	faux_argv_free(args);
	if (candidate_value)
		faux_argv_add(insert_to, candidate_value);

	pline_free(pline);

	return insert_to;
}


int srp_PLINE_INSERT_TO(kcontext_t *context)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	const char *value = NULL;
	pexpr_t *expr = NULL;
	size_t expr_num = 0;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	value = kcontext_candidate_value(context);
	args = assemble_insert_to(sess, kcontext_parent_pargv(context),
		cur_path, value, srp_udata_opts(context));
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid)
		goto err;
	expr_num = faux_list_len(pline->exprs);
	if (expr_num != 1)
		goto err;
	expr = pline_current_expr(pline);
	if (expr->pat & PT_NOT_INSERT)
		goto err;

	ret = 0;
err:
	pline_free(pline);

	return ret;
}


static int srp_compl_or_help_insert_to(kcontext_t *context, bool_t help)
{
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = assemble_insert_to(sess, kcontext_parent_pargv(context),
		cur_path, NULL, srp_udata_opts(context));
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);
	pline_print_completions(pline, help, PT_COMPL_INSERT, BOOL_TRUE);
	pline_free(pline);

	return 0;
}


int srp_compl_insert_to(kcontext_t *context)
{
	return srp_compl_or_help_insert_to(context, BOOL_FALSE);
}


int srp_help_insert_to(kcontext_t *context)
{
	return srp_compl_or_help_insert_to(context, BOOL_TRUE);
}


int srp_set(kcontext_t *context)
{
	int ret = 0;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	faux_list_node_t *iter = NULL;
	pexpr_t *expr = NULL;
	size_t err_num = 0;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid set request\n");
		ret = -1;
		goto cleanup;
	}

	iter = faux_list_head(pline->exprs);
	while ((expr = (pexpr_t *)faux_list_each(&iter))) {
		if (!(expr->pat & PT_SET)) {
			err_num++;
			fprintf(stderr, ERRORMSG "Illegal expression for set operation\n");
			break;
		}
		if (sr_set_item_str(sess, expr->xpath, expr->value, NULL, 0) !=
			SR_ERR_OK) {
			err_num++;
			srp_error(sess, ERRORMSG "Can't set data\n");
			break;
		}
	}
	if (err_num > 0)
		ret = -1;

	if (!sr_has_changes(sess))
		goto cleanup;

	if (err_num > 0) {
		sr_discard_changes(sess);
		goto cleanup;
	}

	if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
		sr_discard_changes(sess);
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		goto cleanup;
	}

cleanup:
	pline_free(pline);

	return ret;
}


int srp_del(kcontext_t *context)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid 'del' request\n");
		goto err;
	}

	if (faux_list_len(pline->exprs) > 1) {
		fprintf(stderr, ERRORMSG "Can't delete more than one object\n");
		goto err;
	}

	expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));

	if (!(expr->pat & PT_DEL)) {
		fprintf(stderr, ERRORMSG "Illegal expression for 'del' operation\n");
		goto err;
	}

	if (sr_delete_item(sess, expr->xpath, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't delete data\n");
		goto err;
	}

	if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
		sr_discard_changes(sess);
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		goto err;
	}

	ret = 0;
err:
	pline_free(pline);

	return ret;
}


int srp_edit(kcontext_t *context)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	faux_argv_t *cur_path = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid 'edit' request\n");
		goto err;
	}

	if (faux_list_len(pline->exprs) > 1) {
		fprintf(stderr, ERRORMSG "Can't process more than one object\n");
		goto err;
	}

	expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));

	if (!(expr->pat & PT_EDIT)) {
		fprintf(stderr, ERRORMSG "Illegal expression for 'edit' operation\n");
		goto err;
	}

	if (sr_set_item_str(sess, expr->xpath, NULL, NULL, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't set editing data\n");
		goto err;
	}

	if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
		sr_discard_changes(sess);
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		goto err;
	}

	// Set new current path
	srp_udata_set_path(context, args);

	ret = 0;
err:
	if (ret < 0)
		faux_argv_free(args);
	pline_free(pline);

	return ret;
}


int srp_top(kcontext_t *context)
{
	assert(context);

	srp_udata_set_path(context, NULL);

	return 0;
}


int srp_up(kcontext_t *context)
{
	sr_session_ctx_t *sess = NULL;
	faux_argv_t *cur_path = NULL;
	faux_argv_node_t *iter = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	if (!cur_path)
		return -1; // It's top level and can't level up

	// Remove last arguments one by one and wait for legal edit-like pline
	while (faux_argv_len(cur_path) > 0) {
		pline_t *pline = NULL;
		pexpr_t *expr = NULL;
		size_t len = 0;

		iter = faux_argv_iterr(cur_path);
		faux_argv_del(cur_path, iter);
		pline = pline_parse(sess, cur_path, srp_udata_opts(context));
		if (pline->invalid) {
			pline_free(pline);
			continue;
		}
		len = faux_list_len(pline->exprs);
		if (len != 1) {
			pline_free(pline);
			continue;
		}
		expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));
		if (!(expr->pat & PT_EDIT)) {
			pline_free(pline);
			continue;
		}
		// Here new path is ok
		pline_free(pline);
		break;
	}

	// Don't store empty path
	if (faux_argv_len(cur_path) == 0)
		srp_udata_set_path(context, NULL);

	return 0;
}


int srp_insert(kcontext_t *context)
{
	int ret = -1;
	pline_t *pline = NULL;
	pline_t *pline_to = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	pexpr_t *expr_to = NULL;
	faux_argv_t *cur_path = NULL;
	faux_argv_t *insert_from = NULL;
	faux_argv_t *insert_to = NULL;
	sr_move_position_t position = SR_MOVE_LAST;
	kpargv_t *pargv = NULL;
	const char *list_keys = NULL;
	const char *leaflist_value = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	pargv = kcontext_pargv(context);

	// 'from' argument
	insert_from = param2argv(cur_path, pargv, ARG_FROM_PATH);
	pline = pline_parse(sess, insert_from, srp_udata_opts(context));
	faux_argv_free(insert_from);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid 'from' expression\n");
		goto err;
	}

	if (faux_list_len(pline->exprs) > 1) {
		fprintf(stderr, ERRORMSG "Can't process more than one object\n");
		goto err;
	}

	expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));

	if (!(expr->pat & PT_INSERT)) {
		fprintf(stderr, ERRORMSG "Illegal 'from' expression for 'insert' operation\n");
		goto err;
	}

	// Position
	if (kpargv_find(pargv, "first"))
		position = SR_MOVE_FIRST;
	else if (kpargv_find(pargv, "last"))
		position = SR_MOVE_LAST;
	else if (kpargv_find(pargv, "before"))
		position = SR_MOVE_BEFORE;
	else if (kpargv_find(pargv, "after"))
		position = SR_MOVE_AFTER;
	else {
		fprintf(stderr, ERRORMSG "Illegal 'position' argument\n");
		goto err;
	}

	// 'to' argument
	if ((SR_MOVE_BEFORE == position) || (SR_MOVE_AFTER == position)) {
		insert_to = assemble_insert_to(sess, pargv, cur_path,
			NULL, srp_udata_opts(context));
		pline_to = pline_parse(sess, insert_to, srp_udata_opts(context));
		faux_argv_free(insert_to);

		if (pline_to->invalid) {
			fprintf(stderr, ERRORMSG "Invalid 'to' expression\n");
			goto err;
		}

		if (faux_list_len(pline_to->exprs) > 1) {
			fprintf(stderr, ERRORMSG "Can't process more than one object\n");
			goto err;
		}

		expr_to = (pexpr_t *)faux_list_data(faux_list_head(pline_to->exprs));

		if (!(expr_to->pat & PT_INSERT)) {
			fprintf(stderr, ERRORMSG "Illegal 'to' expression for 'insert' operation\n");
			goto err;
		}

		if (PAT_LIST_KEY == expr_to->pat)
			list_keys = expr_to->last_keys;
		else // PATH_LEAFLIST_VALUE
			leaflist_value = expr_to->last_keys;
	}

	if (sr_move_item(sess, expr->xpath, position,
		list_keys, leaflist_value, NULL, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't move element\n");
		goto err;
	}

	if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
		sr_discard_changes(sess);
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		goto err;
	}

	ret = 0;
err:
	pline_free(pline);
	pline_free(pline_to);

	return ret;
}


int srp_verify(kcontext_t *context)
{
	int ret = -1;
	sr_session_ctx_t *sess = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	// Validate candidate config
	if (sr_validate(sess, NULL, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Invalid candidate configuration\n");
		goto err;
	}

	ret = 0;
err:

	return ret;
}


int srp_commit(kcontext_t *context)
{
	int ret = -1;
	sr_session_ctx_t *sess = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	// Validate candidate config. The copy operation is not enough to fully
	// verify candidate config. It verifies only the part of it. So verify
	// before commit
	if (sr_validate(sess, NULL, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Invalid candidate configuration\n");
		goto err;
	}

	// Copy candidate to running-config
	if (sr_session_switch_ds(sess, SR_DS_RUNNING)) {
		srp_error(sess, ERRORMSG "Can't connect to running-config data store\n");
		goto err;
	}
	if (sr_copy_config(sess, NULL, SRP_REPO_EDIT, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't commit to running-config\n");
		goto err;
	}

	// Copy running-config to startup-config
	if (sr_session_switch_ds(sess, SR_DS_STARTUP)) {
		srp_error(sess, ERRORMSG "Can't connect to startup-config data store\n");
		goto err;
	}
	if (sr_copy_config(sess, NULL, SR_DS_RUNNING, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't store data to startup-config\n");
		goto err;
	}

	ret = 0;
err:
	sr_session_switch_ds(sess, SRP_REPO_EDIT);

	return ret;
}


int srp_reset(kcontext_t *context)
{
	int ret = -1;
	sr_session_ctx_t *sess = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	// Copy running-config to candidate config
	if (sr_copy_config(sess, NULL, SR_DS_RUNNING, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't reset to running-config\n");
		goto err;
	}

	ret = 0;
err:

	return ret;
}


int srp_show_xml(kcontext_t *context)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	faux_argv_t *cur_path = NULL;
	sr_data_t *data = NULL;
	struct ly_out *out = NULL;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid 'show' request\n");
		goto err;
	}

	if (faux_list_len(pline->exprs) > 1) {
		fprintf(stderr, ERRORMSG "Can't process more than one object\n");
		goto err;
	}

	expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));
	if (!(expr->pat & PT_EDIT)) {
		fprintf(stderr, ERRORMSG "Illegal expression for 'show' operation\n");
		goto err;
	}

	if (sr_get_subtree(sess, expr->xpath, 0, &data) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't get specified subtree\n");
		goto err;
	}
	if (!data) // Not found
		goto err;

	ly_out_new_file(stdout, &out);
	lyd_print_tree(out, data->tree, LYD_XML, 0);
	ly_out_free(out, NULL, 0);
//	child = lyd_child(data->tree);
//	if (child) {
//		ly_out_new_file(stdout, &out);
//		lyd_print_all(out, child, LYD_XML, 0);
//	}

	struct lyd_meta *meta = lyd_find_meta(data->tree->meta, NULL, "junos-configuration-metadata:active");
	if (meta)
		printf("META\n");

	sr_release_data(data);

	ret = 0;
err:
	pline_free(pline);

	return ret;
}


static int show(kcontext_t *context, sr_datastore_t ds,
	const char *path_var, bool_t use_cur_path)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	faux_argv_t *cur_path = NULL;
	char *xpath = NULL;
	size_t xpath_depth = 0;

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	if (ds != SRP_REPO_EDIT)
		sr_session_switch_ds(sess, ds);
	if (use_cur_path)
		cur_path = (faux_argv_t *)srp_udata_path(context);

	if (kpargv_find(kcontext_pargv(context), path_var) || cur_path) {
		args = param2argv(cur_path, kcontext_pargv(context), path_var);
		pline = pline_parse(sess, args, srp_udata_opts(context));
		faux_argv_free(args);

		if (pline->invalid) {
			fprintf(stderr, ERRORMSG "Invalid 'show' request\n");
			goto err;
		}

		if (faux_list_len(pline->exprs) > 1) {
			fprintf(stderr, ERRORMSG "Can't process more than one object\n");
			goto err;
		}

		if (!(expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs)))) {
			fprintf(stderr, ERRORMSG "Can't get expression\n");
			goto err;
		}
		if (!(expr->pat & PT_SHOW)) {
			fprintf(stderr, ERRORMSG "Illegal expression for 'show' operation\n");
			goto err;
		}
		if (!expr->xpath) {
			fprintf(stderr, ERRORMSG "Empty expression for 'show' operation\n");
			goto err;
		}
		xpath = expr->xpath;
		xpath_depth = expr->tree_depth;
	}

	show_xpath(sess, xpath, xpath_depth, srp_udata_opts(context));

	ret = 0;
err:
	pline_free(pline);
	if (ds != SRP_REPO_EDIT)
		sr_session_switch_ds(sess, SRP_REPO_EDIT);

	return ret;
}


static int show_path(kcontext_t *context, bool_t use_cur_path)
{
	sr_datastore_t ds = SRP_REPO_EDIT;
	const char *script = NULL;

	assert(context);
	script = kcontext_script(context);
	if (!faux_str_is_empty(script))
		if (!kly_str2ds(script, strlen(script), &ds))
			ds = SRP_REPO_EDIT;

	return show(context, ds, ARG_PATH, use_cur_path);
}


int srp_show_abs(kcontext_t *context)
{
	return show_path(context, BOOL_FALSE);
}


int srp_show(kcontext_t *context)
{
	return show_path(context, BOOL_TRUE);
}


int srp_deactivate(kcontext_t *context)
{
	int ret = -1;
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	pexpr_t *expr = NULL;
	faux_argv_t *cur_path = NULL;
	sr_data_t *data = NULL;

	assert(context);

	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid 'show' request\n");
		goto err;
	}

	if (faux_list_len(pline->exprs) > 1) {
		fprintf(stderr, ERRORMSG "Can't process more than one object\n");
		goto err;
	}

	expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));
	if (!(expr->pat & PT_DEL)) {
		fprintf(stderr, ERRORMSG "Illegal expression for 'show' operation\n");
		goto err;
	}

	if (sr_get_subtree(sess, expr->xpath, 0, &data) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't get specified subtree\n");
		goto err;
	}
	if (!data) // Not found
		goto err;
	if (lyd_new_meta(LYD_CTX(data->tree), data->tree, NULL,
		"junos-configuration-metadata:active", "false", 0, NULL)) {
		fprintf(stderr, ERRORMSG "Can't deactivate\n");
		goto err;
	}

	struct lyd_meta *meta = lyd_find_meta(data->tree->meta, NULL, "junos-configuration-metadata:active");
	if (meta)
		printf("META\n");

	if (sr_has_changes(sess))
		fprintf(stderr, ERRORMSG "Has changes\n");

	if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
		sr_discard_changes(sess);
		srp_error(sess, ERRORMSG "Can't apply changes\n");
	}
	sr_release_data(data);

	if (sr_get_subtree(sess, expr->xpath, 0, &data) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't get specified subtree\n");
		goto err;
	}
	if (!data) // Not found
		goto err;

	struct ly_out *out = NULL;
	ly_out_new_file(stdout, &out);
	lyd_print_tree(out, data->tree, LYD_XML, 0);
	ly_out_free(out, NULL, 0);

	sr_release_data(data);

	ret = 0;
err:
	pline_free(pline);

	return ret;
}


int srp_diff(kcontext_t *context)
{
	int ret = -1;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	sr_data_t *data1 = NULL;
	sr_data_t *data2 = NULL;
	faux_argv_t *cur_path = NULL;
	const char *xpath = NULL;
	struct lyd_node *diff = NULL;
	pline_opts_t masked_opts = {};

	assert(context);
	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	cur_path = (faux_argv_t *)srp_udata_path(context);

	if (kpargv_find(kcontext_pargv(context), ARG_PATH) || cur_path) {
		faux_argv_t *args = NULL;
		pexpr_t *expr = NULL;

		args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
		pline = pline_parse(sess, args, srp_udata_opts(context));
		faux_argv_free(args);

		if (pline->invalid) {
			fprintf(stderr, ERRORMSG "Invalid 'show' request\n");
			goto err;
		}

		if (faux_list_len(pline->exprs) > 1) {
			fprintf(stderr, ERRORMSG "Can't process more than one object\n");
			goto err;
		}

		if (!(expr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs)))) {
			fprintf(stderr, ERRORMSG "Can't get expression\n");
			goto err;
		}
		if (!(expr->pat & PT_EDIT)) {
			fprintf(stderr, ERRORMSG "Illegal expression for 'show' operation\n");
			goto err;
		}
		if (!expr->xpath) {
			fprintf(stderr, ERRORMSG "Empty expression for 'show' operation\n");
			goto err;
		}
		xpath = expr->xpath;
	}

	if (!xpath)
		xpath = "/*";

	if (sr_get_data(sess, xpath, 0, 0, 0, &data2) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't get specified subtree\n");
		goto err;
	}

	// Running config
	sr_session_switch_ds(sess, SR_DS_RUNNING);

	if (sr_get_data(sess, xpath, 0, 0, 0, &data1) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't get specified subtree\n");
		goto err;
	}

	if (lyd_diff_siblings(data1 ? data1->tree : NULL, data2 ? data2->tree : NULL,
		0, &diff) != LY_SUCCESS) {
		srp_error(sess, ERRORMSG "Can't generate diff\n");
		goto err;
	}

	// Hack to don't show oneliners within diff. Mask oneliners flag
	masked_opts = *srp_udata_opts(context);
	masked_opts.oneliners = BOOL_FALSE;

	show_subtree(diff, 0, DIFF_OP_NONE, &masked_opts, BOOL_FALSE);
	lyd_free_siblings(diff);

	ret = 0;
err:
	if (data1)
		sr_release_data(data1);
	if (data2)
		sr_release_data(data2);

	pline_free(pline);
	sr_session_switch_ds(sess, SRP_REPO_EDIT);

	return ret;
}


int srp_compl_xpath(kcontext_t *context)
{
	sr_session_ctx_t *sess = NULL;
	sr_val_t *vals = NULL;
	size_t val_num = 0;
	size_t i = 0;
	const char *script = NULL;
	const char *raw_xpath = NULL;
	sr_datastore_t ds = SRP_REPO_EDIT;

	assert(context);
	script = kcontext_script(context);
	if (faux_str_is_empty(script))
		return -1;

	if (!kly_parse_ext_xpath(script, &raw_xpath, &ds))
		return -1;

	sess = srp_udata_sr_sess(context);
	if (!sess)
		return -1;

	if (ds != SRP_REPO_EDIT)
		sr_session_switch_ds(sess, ds);

	sr_get_items(sess, raw_xpath, 0, 0, &vals, &val_num);
	for (i = 0; i < val_num; i++) {
		char *tmp = sr_val_to_str(&vals[i]);
		if (!tmp)
			continue;
		printf("%s\n", tmp);
		free(tmp);
	}
	sr_free_values(vals, val_num);

	if (ds != SRP_REPO_EDIT)
		sr_session_switch_ds(sess, SRP_REPO_EDIT);

	return 0;
}


// Function for mass operations.
int srp_mass_op(char op, int fd, sr_datastore_t ds, const faux_argv_t *cur_path,
	const pline_opts_t *opts, const char *user, bool_t stop_on_error)
{
	int ret = -1;
	int err = SR_ERR_OK;
	sr_conn_ctx_t *conn = NULL;
	sr_session_ctx_t *sess = NULL;
	faux_file_t *file = NULL;
	char *line = NULL;
	size_t err_num = 0;
	sr_subscription_ctx_t *nacm_sub = NULL;

	err = sr_connect(SR_CONN_DEFAULT, &conn);
	if (err) {
		fprintf(stderr, "Error: Can't connect to sysrepo\n");
		goto out;
	}
	err = sr_session_start(conn, ds, &sess);
	if (err) {
		fprintf(stderr, "Error: Can't start session\n");
		goto out;
	}

	sr_session_set_orig_name(sess, user);
	// Init NACM session
	if (opts->enable_nacm) {
		if (sr_nacm_init(sess, 0, &nacm_sub) != SR_ERR_OK) {
			fprintf(stderr, "Error: Can't init NACM\n");
			goto out;
		}
		sr_nacm_set_user(sess, user);
	}

	file = faux_file_fdopen(fd);
	if (!file) {
		fprintf(stderr, "Error: Can't open input stream\n");
		goto out;
	}

	while ((line = faux_file_getline(file))) {
		pline_t *pline = NULL;
		faux_argv_t *args = NULL;

		// Don't process empty strings and strings with only spaces
		if (!faux_str_has_content(line)) {
			faux_str_free(line);
			continue;
		}

		// Add current sysrepo path
		if (cur_path)
			args = faux_argv_dup(cur_path);
		else
			args = faux_argv_new();

		faux_argv_parse(args, line);
		pline = pline_parse(sess, args, opts);
		faux_argv_free(args);
		if (!pline || pline->invalid) {
			err_num++;
			fprintf(stderr, "Error: Illegal: %s\n", line);
		} else {
			faux_list_node_t *iter = NULL;
			pexpr_t *expr = NULL;

			iter = faux_list_head(pline->exprs);
			while ((expr = (pexpr_t *)faux_list_each(&iter))) {
				// Set
				if (op == 's') {
					if (!(expr->pat & PT_SET)) {
						err_num++;
						fprintf(stderr, "Error: Illegal expression"
							" for set operation\n");
						break;
					}
					if (sr_set_item_str(sess, expr->xpath,
						expr->value, NULL, 0) != SR_ERR_OK) {
						err_num++;
						fprintf(stderr, "Error: Can't set data\n");
						break;
					}
				// Del
				} else if (op == 'd') {
					if (!(expr->pat & PT_DEL)) {
						err_num++;
						fprintf(stderr, "Error: Illegal expression"
							" for del operation\n");
						break;
					}
					if (sr_delete_item(sess, expr->xpath, 0) !=
						SR_ERR_OK) {
						err_num++;
						fprintf(stderr, "Error: Can't del data\n");
						break;
					}
				} else {
					err_num++;
					fprintf(stderr, "Error: Illegal operation '%c'\n",
						op);
					break;
				}
			}
		}
		if (stop_on_error && (err_num > 0)) {
			sr_discard_changes(sess);
			goto out;
		}
		pline_free(pline);
		faux_str_free(line);
	}

	if (sr_has_changes(sess)) {
		if (sr_apply_changes(sess, 0) != SR_ERR_OK) {
			sr_discard_changes(sess);
			fprintf(stderr, "Error: Can't apply changes\n");
			goto out;
		}
	}

	ret = 0;
out:
	faux_file_close(file);
	if (opts->enable_nacm) {
		sr_unsubscribe(nacm_sub);
		sr_nacm_destroy();
	}
	sr_disconnect(conn);

	return ret;
}


// Function for mass config strings load. It can load stream of KPath strings
// (without "set" command, only path and value). Function doesn't use
// pre-connected session because it can be executed within FILTER or utility.
int srp_mass_set(int fd, sr_datastore_t ds, const faux_argv_t *cur_path,
	const pline_opts_t *opts, const char *user, bool_t stop_on_error)
{
	return srp_mass_op('s', fd, ds, cur_path, opts, user, stop_on_error);
}


// Function for mass config strings deletion. It can get stream of KPath strings
// (without "del" command, only path). Function doesn't use
// pre-connected session because it can be executed within FILTER or utility.
int srp_mass_del(int fd, sr_datastore_t ds, const faux_argv_t *cur_path,
	const pline_opts_t *opts, const char *user, bool_t stop_on_error)
{
	return srp_mass_op('d', fd, ds, cur_path, opts, user, stop_on_error);
}
