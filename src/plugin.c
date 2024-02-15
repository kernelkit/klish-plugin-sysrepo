/*
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <syslog.h>
#include <sysrepo.h>
#include <sysrepo/netconf_acm.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/ini.h>
#include <faux/conv.h>
#include <klish/kplugin.h>
#include <klish/kcontext.h>

#include "private.h"


const uint8_t kplugin_sysrepo_major = KPLUGIN_MAJOR;
const uint8_t kplugin_sysrepo_minor = KPLUGIN_MINOR;

static int parse_plugin_conf(const char *conf, pline_opts_t *opts);

static int kplugin_sysrepo_init_session(kcontext_t *context);
static int kplugin_sysrepo_fini_session(kcontext_t *context);


int kplugin_sysrepo_init(kcontext_t *context)
{
	kplugin_t *plugin = NULL;
	srp_udata_t *udata = NULL;

	assert(context);
	plugin = kcontext_plugin(context);
	assert(plugin);

	// Symbols

	// Session init/fini
	kplugin_set_init_session_fn(plugin, kplugin_sysrepo_init_session);
	kplugin_set_fini_session_fn(plugin, kplugin_sysrepo_fini_session);

	// Types
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_SET", srp_PLINE_SET,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_DEL", srp_PLINE_DEL,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_EDIT", srp_PLINE_EDIT,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_EDIT_ABS", srp_PLINE_EDIT_ABS,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_INSERT_FROM", srp_PLINE_INSERT_FROM,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_INSERT_TO", srp_PLINE_INSERT_TO,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));

	// Completion/Help/Prompt
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl", srp_compl,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help", srp_help,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_set", srp_compl_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_set", srp_help_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_del", srp_compl_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_del", srp_help_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_edit", srp_compl_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_edit_abs", srp_compl_edit_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_edit", srp_help_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_edit_abs", srp_help_edit_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_insert", srp_compl_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_insert", srp_help_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_insert_to", srp_compl_insert_to,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_insert_to", srp_help_insert_to,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_prompt_edit_path", srp_prompt_edit_path,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_xpath", srp_compl_xpath,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_prompt", srp_prompt,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));

	// Interactive operations
	kplugin_add_syms(plugin, ksym_new("srp_helper", srp_helper));

	// Operations
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_text", srp_help_text,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_set", srp_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_del", srp_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	// Note: 'edit', 'top', 'up'  must be sync to set current path
	kplugin_add_syms(plugin, ksym_new_ext("srp_edit", srp_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_top", srp_top,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_up", srp_up,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_insert", srp_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_verify", srp_verify,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_commit", srp_commit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_reset", srp_reset,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_show_abs", srp_show_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_show", srp_show,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_diff", srp_diff,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));
	kplugin_add_syms(plugin, ksym_new_ext("srp_deactivate", srp_deactivate,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC));

	// User-data initialization
	udata = faux_zmalloc(sizeof(*udata));
	assert(udata);
	udata->path = NULL;
	udata->sr_conn = NULL;
	udata->sr_sess = NULL;
	udata->nacm_sub = NULL;

	// Settings
	udata->opts.begin_bracket = '{';
	udata->opts.end_bracket = '}';
	udata->opts.show_brackets = BOOL_TRUE;
	udata->opts.show_semicolons = BOOL_TRUE;
	udata->opts.first_key_w_stmt = BOOL_FALSE;
	udata->opts.keys_w_stmt = BOOL_TRUE;
	udata->opts.colorize = BOOL_TRUE;
	udata->opts.indent = 2;
	udata->opts.default_keys = BOOL_FALSE;
	udata->opts.show_default_keys = BOOL_FALSE;
	udata->opts.hide_passwords = BOOL_TRUE;
	udata->opts.enable_nacm = BOOL_FALSE;
	udata->opts.oneliners = BOOL_TRUE;
	parse_plugin_conf(kplugin_conf(plugin), &udata->opts);

	kplugin_set_udata(plugin, udata);

	// Logging
	ly_log_options(LY_LOSTORE);

	return 0;
}


int kplugin_sysrepo_fini(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	// Free plugin's user-data
	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);
	if (udata->path)
		faux_argv_free(udata->path);
	faux_free(udata);

	return 0;
}


pline_opts_t *srp_udata_opts(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);

	return &udata->opts;
}


faux_argv_t *srp_udata_path(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);

	return udata->path;
}


void srp_udata_set_path(kcontext_t *context, faux_argv_t *path)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);
	if (udata->path)
		faux_argv_free(udata->path);
	udata->path = path;
}


sr_session_ctx_t *srp_udata_sr_sess(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);

	return udata->sr_sess;
}


static int parse_plugin_conf(const char *conf, pline_opts_t *opts)
{
	faux_ini_t *ini = NULL;
	const char *val = NULL;

	if (!opts)
		return -1;
	if (!conf)
		return 0; // Use defaults

	ini = faux_ini_new();
	if (!faux_ini_parse_str(ini, conf)) {
		faux_ini_free(ini);
		return -1;
	}

	if ((val = faux_ini_find(ini, "ShowBrackets"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->show_brackets = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->show_brackets = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "ShowSemicolons"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->show_semicolons = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->show_semicolons = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "FirstKeyWithStatement"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->first_key_w_stmt = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->first_key_w_stmt = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "KeysWithStatement"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->keys_w_stmt = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->keys_w_stmt = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "Colorize"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->colorize = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->colorize = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "Indent"))) {
		unsigned char indent = 0;
		if (faux_conv_atouc(val, &indent, 10))
			opts->indent = indent;
	}

	if ((val = faux_ini_find(ini, "DefaultKeys"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->default_keys = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->default_keys = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "ShowDefaultKeys"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->show_default_keys = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->show_default_keys = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "HidePasswords"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->hide_passwords = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->hide_passwords = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "EnableNACM"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->enable_nacm = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->enable_nacm = BOOL_FALSE;
	}

	if ((val = faux_ini_find(ini, "Oneliners"))) {
		if (faux_str_cmp(val, "y") == 0)
			opts->oneliners = BOOL_TRUE;
		else if (faux_str_cmp(val, "n") == 0)
			opts->oneliners = BOOL_FALSE;
	}

	faux_ini_free(ini);

	return 0;
}


static int kplugin_sysrepo_init_session(kcontext_t *context)
{
	srp_udata_t *udata = NULL;
	const char *user = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);

	// Remote user name
	user = ksession_user(kcontext_session(context));

	// Connect to Sysrepo
	if (sr_connect(SR_CONN_DEFAULT, &(udata->sr_conn))) {
		syslog(LOG_ERR, "Can't connect to Sysrepo");
		return -1;
	}
	if (sr_session_start(udata->sr_conn, SRP_REPO_EDIT, &(udata->sr_sess))) {
		syslog(LOG_ERR, "Can't connect create Sysrepo session");
		sr_disconnect(udata->sr_conn);
		return -1;
	}
	sr_session_set_orig_name(udata->sr_sess, user);
	// Init NACM session
	if (udata->opts.enable_nacm) {
		if (sr_nacm_init(udata->sr_sess, 0, &(udata->nacm_sub)) != SR_ERR_OK) {
			sr_disconnect(udata->sr_conn);
			return -1;
		}
		sr_nacm_set_user(udata->sr_sess, user);
	}

	syslog(LOG_INFO, "Start SysRepo session for \"%s\"", user);

	return 0;
}


static int kplugin_sysrepo_fini_session(kcontext_t *context)
{
	srp_udata_t *udata = NULL;
	const char *user = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_udata(context);
	assert(udata);

	// Remote user name
	user = ksession_user(kcontext_session(context));

	if (udata->opts.enable_nacm) {
		sr_unsubscribe(udata->nacm_sub);
		sr_nacm_destroy();
	}
	sr_disconnect(udata->sr_conn);

	syslog(LOG_INFO, "Stop SysRepo session for \"%s\"", user ? user : "<unknown>");

	return 0;
}
