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

#include "klish_plugin_sysrepo.h"


const uint8_t kplugin_sysrepo_major = KPLUGIN_MAJOR;
const uint8_t kplugin_sysrepo_minor = KPLUGIN_MINOR;

static int kplugin_sysrepo_init_session(kcontext_t *context);
static int kplugin_sysrepo_fini_session(kcontext_t *context);


static bool_t free_udata(void *data)
{
	srp_udata_t *udata = (srp_udata_t *)data;

	assert(udata);
	if (udata->path)
		faux_argv_free(udata->path);
	faux_free(udata);

	return BOOL_TRUE;
}


int kplugin_sysrepo_init(kcontext_t *context)
{
	kplugin_t *plugin = NULL;
	srp_udata_t *udata = NULL;
	kscheme_t *scheme = NULL;

	assert(context);
	plugin = kcontext_plugin(context);
	assert(plugin);
	scheme = kcontext_scheme(context);
	assert(scheme);

	// Symbols

	// Session init/fini
	kplugin_set_init_session_fn(plugin, kplugin_sysrepo_init_session);
	kplugin_set_fini_session_fn(plugin, kplugin_sysrepo_fini_session);

	// Types
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_SET", srp_PLINE_SET,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_DEL", srp_PLINE_DEL,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_EDIT", srp_PLINE_EDIT,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_EDIT_ABS", srp_PLINE_EDIT_ABS,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_INSERT_FROM", srp_PLINE_INSERT_FROM,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("PLINE_INSERT_TO", srp_PLINE_INSERT_TO,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));

	// Completion/Help/Prompt
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl", srp_compl,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help", srp_help,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_set", srp_compl_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_set", srp_help_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_del", srp_compl_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_del", srp_help_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_edit", srp_compl_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_edit_abs", srp_compl_edit_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_edit", srp_help_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_edit_abs", srp_help_edit_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_insert", srp_compl_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_insert", srp_help_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_insert_to", srp_compl_insert_to,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_help_insert_to", srp_help_insert_to,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_prompt_edit_path", srp_prompt_edit_path,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_compl_xpath", srp_compl_xpath,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));

	// Operations
	kplugin_add_syms(plugin, ksym_new_ext("srp_set", srp_set,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_del", srp_del,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	// Note: 'edit', 'top', 'up'  must be sync to set current path
	kplugin_add_syms(plugin, ksym_new_ext("srp_edit", srp_edit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_top", srp_top,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_up", srp_up,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_SILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_insert", srp_insert,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_verify", srp_verify,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_commit", srp_commit,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_reset", srp_reset,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_show_abs", srp_show_abs,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_show", srp_show,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_diff", srp_diff,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));
	kplugin_add_syms(plugin, ksym_new_ext("srp_deactivate", srp_deactivate,
		KSYM_USERDEFINED_PERMANENT, KSYM_SYNC, KSYM_NONSILENT));

	// User-data initialization
	udata = faux_zmalloc(sizeof(*udata));
	assert(udata);
	udata->path = NULL;
	udata->sr_conn = NULL;
	udata->sr_sess = NULL;
	udata->nacm_sub = NULL;

	// Settings
	pline_opts_init(&udata->opts);
	pline_opts_parse(kplugin_conf(plugin), &udata->opts);

	if (!kscheme_named_udata_new(scheme, SRP_UDATA_NAME, udata, free_udata))
		syslog(LOG_ERR, "Can't create name udata \"%s\"", SRP_UDATA_NAME);

	// Logging
	ly_log_options(LY_LOSTORE);

	return 0;
}


int kplugin_sysrepo_fini(kcontext_t *context)
{
	context = context;

	return 0;
}


srp_udata_t *srp_udata(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = (srp_udata_t *)kcontext_named_udata(context, SRP_UDATA_NAME);
	assert(udata);

	return udata;
}


pline_opts_t *srp_udata_opts(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = srp_udata(context);
	assert(udata);

	return &udata->opts;
}


faux_argv_t *srp_udata_path(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = srp_udata(context);
	assert(udata);

	return udata->path;
}


void srp_udata_set_path(kcontext_t *context, faux_argv_t *path)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = srp_udata(context);
	assert(udata);
	if (udata->path)
		faux_argv_free(udata->path);
	udata->path = path;
}


sr_session_ctx_t *srp_udata_sr_sess(kcontext_t *context)
{
	srp_udata_t *udata = NULL;

	assert(context);

	udata = srp_udata(context);
	assert(udata);

	return udata->sr_sess;
}


static int kplugin_sysrepo_init_session(kcontext_t *context)
{
	srp_udata_t *udata = NULL;
	const char *user = NULL;

	assert(context);

	udata = srp_udata(context);
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

	udata = srp_udata(context);
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
