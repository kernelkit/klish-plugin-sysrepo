#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/argv.h>
#include <faux/list.h>
#include <faux/error.h>
#include <faux/sysdb.h>

#include <klish/khelper.h>
#include <klish/kplugin.h>
#include <klish/kentry.h>
#include <klish/kscheme.h>
#include <klish/kcontext.h>
#include <klish/kpargv.h>
#include <klish/kpath.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>

#include "pline.h"
#include "private.h"

#define ERRORMSG "Error: "

#define ARG_PATH "path"
#define ARG_FROM_PATH "from_path"
#define ARG_TO_PATH "to_path"

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1)
		return NULL;

	p = str + strlen(str) - 1;
        while (p >= str && *p == '\n')
		*p-- = 0;

	return str;
}

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
	pt_e enabled_ptypes, bool_t use_cur_path)
{
	faux_argv_t *args = NULL;
	pline_t *pline = NULL;
	sr_session_ctx_t *sess = NULL;
	const char *entry_name = NULL;
	faux_argv_t *cur_path = NULL;

	assert(context);

	sess = srp_udata_sr_sess(context);

	if (use_cur_path)
		cur_path = (faux_argv_t *)srp_udata_path(context);
	entry_name = kentry_name(kcontext_candidate_entry(context));
	args = param2argv(cur_path, kcontext_parent_pargv(context), entry_name);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);
	pline_print_completions(pline, help, enabled_ptypes);
	pline_free(pline);

	return 0;
}


int srp_compl(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_ALL, BOOL_TRUE);
}


int srp_help(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_ALL, BOOL_TRUE);
}


int srp_compl_set(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_SET, BOOL_TRUE);
}


int srp_help_set(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_SET, BOOL_TRUE);
}


int srp_compl_del(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_DEL, BOOL_TRUE);
}


int srp_help_del(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_DEL, BOOL_TRUE);
}


int srp_compl_edit(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_EDIT, BOOL_TRUE);
}


int srp_compl_edit_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_EDIT, BOOL_FALSE);
}


int srp_help_edit(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_EDIT, BOOL_TRUE);
}


int srp_help_edit_abs(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_EDIT, BOOL_FALSE);
}


int srp_compl_insert(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_FALSE, PT_COMPL_INSERT, BOOL_TRUE);
}


int srp_help_insert(kcontext_t *context)
{
	return srp_compl_or_help(context, BOOL_TRUE, PT_COMPL_INSERT, BOOL_TRUE);
}


/*
 * Shorten a path for prompt display if it exceeds the threshold.
 * Keeps first element and last 3 elements, replaces middle with /…/
 * This prioritizes showing the deepest (most relevant) context.
 */
static char *shorten_path_for_prompt(faux_argv_t *path)
{
	const size_t MAX_PROMPT_PATH_LEN = 20;
	const size_t KEEP_FIRST = 1;
	const size_t KEEP_LAST = 3;
	char *full_path = NULL;
	char *result = NULL;
	faux_argv_node_t *iter = NULL;
	const char *arg = NULL;
	size_t idx = 0;
	size_t len = 0;
	bool_t ellipsis_added = BOOL_FALSE;

	if (!path)
		return NULL;

	// Build full path string to check length
	iter = faux_argv_iter(path);
	while ((arg = faux_argv_each(&iter))) {
		faux_str_cat(&full_path, "/");
		faux_str_cat(&full_path, arg);
	}

	if (!full_path)
		return NULL;

	// If short enough or too few elements, return as-is
	len = faux_argv_len(path);
	if (strlen(full_path) <= MAX_PROMPT_PATH_LEN || len <= (KEEP_FIRST + KEEP_LAST)) {
		return full_path;
	}

	// Need to shorten: build new string with ellipsis
	faux_str_free(full_path);

	iter = faux_argv_iter(path);
	while ((arg = faux_argv_each(&iter))) {
		if (idx < KEEP_FIRST) {
			// Keep first N elements
			faux_str_cat(&result, "/");
			faux_str_cat(&result, arg);
		} else if (idx >= len - KEEP_LAST) {
			// Add ellipsis before last N elements
			if (!ellipsis_added) {
				faux_str_cat(&result, "/…");
				ellipsis_added = BOOL_TRUE;
			}
			faux_str_cat(&result, "/");
			faux_str_cat(&result, arg);
		}
		// Skip middle elements
		idx++;
	}

	return result;
}


int srp_prompt_edit_path(kcontext_t *context)
{
	faux_argv_t *cur_path = NULL;
	char *path = NULL;

	assert(context);

	cur_path = (faux_argv_t *)srp_udata_path(context);
	if (cur_path)
		path = shorten_path_for_prompt(cur_path);
	printf("[edit%s%s]\n", path ? " " : "", path ? path : "");
	faux_str_free(path);

	return 0;
}


/*
 * sysrepo version of klish_prompt() default.
 */
int srp_prompt(kcontext_t *context)
{
	bool_t is_macro = BOOL_FALSE;
	kpath_levels_node_t *iter;
	faux_argv_t *cur_path;
	ksession_t *session;
	char *prompt = NULL;
	struct utsname uts;
	const char *script;
	const char *start;
	const char *user;
	const char *pos;
	klevel_t *level;

	script = kcontext_script(context);
	if (faux_str_is_empty(script))
		return 0;
	pos = script;
	start = script;

	while (*pos != '\0') {
		if (is_macro) {
			switch (*pos) {
			case '%':
				faux_str_cat(&prompt, "%");
				break;
			case 'h':
				if (uname(&uts) == 0)
					faux_str_cat(&prompt, uts.nodename);
				break;
			case 'u':
				user = ksession_user(kcontext_session(context));
				if (user)
					faux_str_cat(&prompt, user);
				break;
			case 'w':
				session = kcontext_session(context);
				if (!session)
					break;

				iter = kpath_iter(ksession_path(session));
				while ((level = kpath_each(&iter))) {
					const char *nm = kentry_name(klevel_entry(level));

					faux_str_cat(&prompt, "/");
					faux_str_cat(&prompt, nm);
				}
				break;
			case 'x':
				cur_path = (faux_argv_t *)srp_udata_path(context);
				if (cur_path) {
					char *path_str = shorten_path_for_prompt(cur_path);
					if (path_str) {
						faux_str_cat(&prompt, path_str);
						faux_str_free(path_str);
					}
				}
				break;
			}
			is_macro = BOOL_FALSE;
			start = pos + 1;
		} else if (*pos == '%') {
			is_macro = BOOL_TRUE;
			if (pos > start)
				faux_str_catn(&prompt, start, pos - start);
		}
		pos++;
	}
	if (pos > start)
		faux_str_catn(&prompt, start, pos - start);

	printf("%s", prompt);
	faux_str_free(prompt);
	fflush(stdout);

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

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = assemble_insert_to(sess, kcontext_parent_pargv(context),
		cur_path, NULL, srp_udata_opts(context));
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);
	pline_print_completions(pline, help, PT_COMPL_INSERT);
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

/* Extracts YANG model description text for a 'help foo' command */
int srp_help_text(kcontext_t *context)
{
	sr_session_ctx_t *sess = NULL;
	sr_conn_ctx_t *conn = NULL;
	faux_argv_t *args = NULL;
	faux_argv_t *cur_path;
	pline_t *pline;
	int ret = 0;

	assert(context);

	if (sr_connect(SR_CONN_DEFAULT, &conn))
		return -1;
	if (sr_session_start(conn, SRP_REPO_EDIT, &sess)) {
		sr_disconnect(conn);
		return -1;
	}

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), "path");
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid help request\n");
		ret = -1;
		goto cleanup;
	}

	pline_print_help(pline);
cleanup:
	pline_free(pline);
	sr_disconnect(conn);

	return ret;
}

LY_DATA_TYPE node_type(sr_session_ctx_t *sess, const char *xpath)
{
	LY_DATA_TYPE rc = LY_TYPE_UNKNOWN;
	const struct lysc_node *schema;
	const struct lysc_type *type;
	const struct ly_ctx *ctx;
	sr_conn_ctx_t *conn;

	conn = sr_session_get_connection(sess);
	ctx = sr_acquire_context(conn);
	if (ctx) {
		schema = lys_find_path(ctx, NULL, xpath, 0);
		if (schema && (schema->nodetype & LYS_LEAF)) {
			type = ((const struct lysc_node_leaf *)schema)->type;
			if (type)
				rc = type->basetype;
		}
		sr_release_context(conn);
	}

	return rc;
}

// Notify user when a leaf node with a default vslue is removed.
static void notify_on_delete(sr_session_ctx_t *sess, const char *xpath)
{
	LY_DATA_TYPE type = LY_TYPE_UNKNOWN;
	const struct lysc_node *schema;
	const struct ly_ctx *ctx;
	const char *dflt = NULL;
	sr_conn_ctx_t *conn;

	conn = sr_session_get_connection(sess);
	ctx = sr_acquire_context(conn);
	if (!ctx)
		return;

	schema = lys_find_path(ctx, NULL, xpath, 0);
	if (schema && (schema->nodetype & LYS_LEAF)) {
		const struct lysc_node_leaf *leaf = (struct lysc_node_leaf *)schema;

		type = leaf->type->basetype;
		if (leaf->dflt.str)
			dflt = leaf->dflt.str;
	}

	sr_release_context(conn);

	if (dflt && (type == LY_TYPE_BOOL   ||
		     type == LY_TYPE_INT8   || type == LY_TYPE_INT16  ||
		     type == LY_TYPE_INT32  || type == LY_TYPE_INT64  ||
		     type == LY_TYPE_UINT8  || type == LY_TYPE_UINT16 ||
		     type == LY_TYPE_UINT32 || type == LY_TYPE_UINT64)) {
		const char *nm;

		nm = strrchr(xpath, '/');
		if (nm)
			nm++;
		else
			nm = xpath;

		printf("NOTE: %s was reset to its default value: %s\n", nm, dflt);
	}
}

static int is_pwd(const char *xpath)
{
	if (strstr(xpath, "/ietf-system:password"))
		return 1;

	return 0;
}

static int run(const char *cmd)
{
	char command[strlen(cmd) +  32];
	int rc;

	snprintf(command, sizeof(command), "env CLISH=yes /bin/sh -c '%s'", cmd);
	rc = system(command);
	if (rc == -1)
		return -1;

	if (WIFEXITED(rc))
		rc = WEXITSTATUS(rc);
	else if (WIFSIGNALED(rc))
		rc = -2;

	return rc;
}

/*
 * Instead of srp_set(), which requries a value, this calls an external
 * helper command to construct the value.
 */
int srp_helper(kcontext_t *context)
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

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid set request.\n");
		ret = -1;
		goto cleanup;
	}

	iter = faux_list_head(pline->exprs);
	while ((expr = (pexpr_t *)faux_list_each(&iter))) {
		LY_DATA_TYPE type;
		mode_t omask;

		if (expr->pat & PT_SET) {
			fprintf(stderr, ERRORMSG "command does not take value, try 'set key value'\n");
			err_num++;
			break;
		}

		if (!expr->xpath) {
			fprintf(stderr, ERRORMSG "Invalid path specified\n");
			err_num++;
			break;
		}

		omask = umask(0177);

		type = node_type(sess, expr->xpath);
		if (type == LY_TYPE_UNKNOWN) {
			fprintf(stderr, ERRORMSG "Path does not exist or is not a leaf node: %s\n", expr->xpath);
			err_num++;
			goto fail;
		}

		if (type == LY_TYPE_BINARY) {
			char fn[] = "/tmp/editor.XXXXXX";
			char buf[BUFSIZ];
			sr_val_t *val = NULL;
			FILE *fp;
			int fd;
			int rc;

			fd = mkstemp(fn);
			if (fd == -1) {
				err_num++;
				goto fail;
			}
			close(fd);

			// Try to get existing value from sysrepo
			rc = sr_get_item(sess, expr->xpath, 0, &val);
			if (rc == SR_ERR_OK && val) {
				snprintf(buf, sizeof(buf), "base64 -d > %s", fn);
				fp = popen(buf, "w");
				if (!fp) {
					unlink(fn);
					sr_free_val(val);
					err_num++;
					goto fail;
				}
				fputs(val->data.binary_val, fp);
				pclose(fp);
				sr_free_val(val);
			} else if (rc != SR_ERR_OK && rc != SR_ERR_NOT_FOUND) {
				// Error other than "not found" - this is a real problem
				srp_error(sess, ERRORMSG "Cannot fetch current value\n");
				unlink(fn);
				err_num++;
				goto fail;
			}
			// else if SR_ERR_NOT_FOUND, we'll just edit an empty file (new value)

			snprintf(buf, sizeof(buf), "editor %s", fn);
			if ((ret = run(buf))) {
				unlink(fn);
				err_num++;
				goto fail;
			}

			snprintf(buf, sizeof(buf), "base64 -w 0 %s", fn);
			fp = popen(buf, "r");
			if (!fp) {
				unlink(fn);
				err_num++;
				goto fail;
			}

			if (fgets(buf, sizeof(buf), fp)) {
				chomp(buf);
				if (expr->value)
					free(expr->value);
				expr->value = strdup(buf);
				pclose(fp);
			} else {
				pclose(fp);
				unlink(fn);
				err_num++;
				goto fail;
			}

			unlink(fn);
		} else if (type == LY_TYPE_STRING && is_pwd(expr->xpath)) {
			char fn[] = "/tmp/editor.XXXXXX";
			char buf[256];
			FILE *fp;
			int fd;

			fd = mkstemp(fn);
			if (fd == -1) {
				err_num++;
				goto fail;
			}
			close(fd);

			snprintf(buf, sizeof(buf), "askpass %s", fn);
			if ((ret = run(buf))) {
				unlink(fn);
				err_num++;
				goto fail;
			}

			fp = fopen(fn, "r");
			if (!fp) {
				unlink(fn);
				err_num++;
				goto fail;
			}

			if (fgets(buf, sizeof(buf), fp)) {
				chomp(buf);
				if (expr->value)
					free(expr->value);
				expr->value = strdup(buf);
				fclose(fp);
			} else {
				fclose(fp);
				unlink(fn);
				err_num++;
				goto fail;
			}
			unlink(fn);
		} else {
			fprintf(stderr, ERRORMSG "No command available for this data type, try 'set' instead.\n");
			err_num++;
			goto fail;
		}

	fail:
		umask(omask);

		// Only try to set the value if we haven't encountered errors
		if (err_num > 0)
			break;

		// Ensure we have a value to set
		if (!expr->value) {
			err_num++;
			break;
		}

		if (sr_set_item_str(sess, expr->xpath, expr->value, NULL, 0) != SR_ERR_OK) {
			err_num++;
			srp_error(sess, ERRORMSG "Failed saving data.\n");
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
		srp_error(sess, ERRORMSG "Failed applying changes (1).\n");
		sr_discard_changes(sess);
		goto cleanup;
	}

cleanup:
	pline_free(pline);

	return ret;
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

	cur_path = (faux_argv_t *)srp_udata_path(context);
	args = param2argv(cur_path, kcontext_pargv(context), ARG_PATH);
	pline = pline_parse(sess, args, srp_udata_opts(context));
	faux_argv_free(args);

	if (pline->invalid) {
		fprintf(stderr, ERRORMSG "Invalid set request.\n");
		ret = -1;
		goto cleanup;
	}

	iter = faux_list_head(pline->exprs);
	while ((expr = (pexpr_t *)faux_list_each(&iter))) {
		if (!(expr->pat & PT_SET)) {
			LY_DATA_TYPE type;

			type = node_type(sess, expr->xpath);
			if (type == LY_TYPE_BOOL) {
				if (expr->value)
					free(expr->value);
				expr->value = strdup("true");
			} else {
				err_num++;
				fprintf(stderr, ERRORMSG "Illegal expression for set operation\n");
				break;
			}
		}

		if (sr_set_item_str(sess, expr->xpath, expr->value, NULL, 0) != SR_ERR_OK) {
			err_num++;
			srp_error(sess, ERRORMSG "Failed setting data.\n");
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
		srp_error(sess, ERRORMSG "Failed applying changes (2).\n");
		sr_discard_changes(sess);
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
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		sr_discard_changes(sess);
		goto err;
	}

	notify_on_delete(sess, expr->xpath);
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
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		sr_discard_changes(sess);
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
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		sr_discard_changes(sess);
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

#if 0
	// Copy running-config to startup-config
	if (sr_session_switch_ds(sess, SR_DS_STARTUP)) {
		srp_error(sess, ERRORMSG "Can't connect to startup-config data store\n");
		goto err;
	}
	if (sr_copy_config(sess, NULL, SR_DS_RUNNING, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't store data to startup-config\n");
		goto err;
	}
#endif

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

	// Copy running-config to candidate config
	if (sr_copy_config(sess, NULL, SR_DS_RUNNING, 0) != SR_ERR_OK) {
		srp_error(sess, ERRORMSG "Can't reset to running-config\n");
		goto err;
	}

	ret = 0;
err:

	return ret;
}


int srp_rpc(kcontext_t *context)
{
	kpargv_pargs_node_t *iter;
	size_t icnt = 0, ocnt = 0;
	sr_val_t *input = NULL;
	sr_session_ctx_t *sess;
	const char *xpath;
	sr_val_t *output;
	kparg_t *parg;
	int err;

	assert(context);
	xpath = kcontext_script(context);
	if (!xpath) {
		fprintf(stderr, ERRORMSG "cannot find rpc xpath\n");
		return -1;
	}

	iter = kpargv_pargs_iter(kcontext_pargv(context));
	while ((parg = kpargv_pargs_each(&iter))) {
		const char *key = kentry_name(kparg_entry(parg));
		const char *val = kparg_value(parg);

		/* skip leading part of command line: 'set datetime' */
//		fprintf(stderr, "%s(): got key %s val %s\n", __func__, key, val ?: "<NIL>");
		if (!val || !strcmp(key, val))
			continue;

		sr_realloc_values(icnt, icnt + 1, &input);
		/* e.g. /ietf-system:set-current-datetime/current-datetime */
		sr_val_build_xpath(&input[icnt], "%s/%s", xpath, key);
		sr_val_set_str_data(&input[icnt++], SR_STRING_T, val);
	}

//	fprintf(stderr, "%s(): sending RPC %s, icnt %zu\n", __func__, xpath, icnt);
	sess = srp_udata_sr_sess(context);
	if ((err = sr_rpc_send(sess, xpath, input, icnt, 0, &output, &ocnt))) {
		srp_error(sess, ERRORMSG "failed sending RPC %s: %s\n", xpath, sr_strerror(err));
		sr_free_values(input, icnt);
		return -1;
	}

	for (size_t i = 0; i < ocnt; i++) {
		sr_print_val(&output[i]);
		puts("");
	}

	sr_free_values(input, icnt);
	sr_free_values(output, ocnt);

	return 0;
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

	assert(context);

	sess = srp_udata_sr_sess(context);
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
		if (!expr->xpath) {
			fprintf(stderr, ERRORMSG "Empty expression for 'show' operation\n");
			goto err;
		}
		xpath = expr->xpath;
	}

	show_xpath(sess, xpath, srp_udata_opts(context));

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
		srp_error(sess, ERRORMSG "Can't apply changes\n");
		sr_discard_changes(sess);
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
