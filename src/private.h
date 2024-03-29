/*
 * private.h
 */

#ifndef _pligin_sysrepo_private_h
#define _plugin_sysrepo_private_h

#include <sysrepo.h>
#include <faux/faux.h>
#include <faux/argv.h>
#include <klish/kcontext_base.h>

#include "pline.h"


// Plugin's user-data structure
typedef struct {
	faux_argv_t *path; // Current data hierarchy path ('edit' operation)
	pline_opts_t opts; // Settings
	sr_conn_ctx_t *sr_conn; // Sysrepo connection
	sr_session_ctx_t *sr_sess; // Sysrepo session
	sr_subscription_ctx_t *nacm_sub;
} srp_udata_t;


// Repository to edit with srp commands
#define SRP_REPO_EDIT SR_DS_CANDIDATE


C_DECL_BEGIN

// Types
int srp_PLINE_SET(kcontext_t *context);
int srp_PLINE_DEL(kcontext_t *context);
int srp_PLINE_EDIT(kcontext_t *context);
int srp_PLINE_EDIT_ABS(kcontext_t *context);
int srp_PLINE_INSERT_FROM(kcontext_t *context);
int srp_PLINE_INSERT_TO(kcontext_t *context);

// Completion/Help/Prompt
int srp_compl(kcontext_t *context);
int srp_help(kcontext_t *context);
int srp_compl_set(kcontext_t *context);
int srp_help_set(kcontext_t *context);
int srp_compl_del(kcontext_t *context);
int srp_help_del(kcontext_t *context);
int srp_compl_edit(kcontext_t *context);
int srp_compl_edit_abs(kcontext_t *context);
int srp_help_edit(kcontext_t *context);
int srp_help_edit_abs(kcontext_t *context);
int srp_compl_insert(kcontext_t *context);
int srp_help_insert(kcontext_t *context);
int srp_compl_insert_to(kcontext_t *context);
int srp_help_insert_to(kcontext_t *context);
int srp_prompt_edit_path(kcontext_t *context);
int srp_compl_xpath(kcontext_t *context);

// Operations
int srp_set(kcontext_t *context);
int srp_del(kcontext_t *context);
int srp_edit(kcontext_t *context);
int srp_top(kcontext_t *context);
int srp_up(kcontext_t *context);
int srp_insert(kcontext_t *context);
int srp_verify(kcontext_t *context);
int srp_commit(kcontext_t *context);
int srp_reset(kcontext_t *context);
int srp_show_abs(kcontext_t *context);
int srp_show(kcontext_t *context);
int srp_diff(kcontext_t *context);
int srp_deactivate(kcontext_t *context);

// Plugin's user-data service functions
pline_opts_t *srp_udata_opts(kcontext_t *context);
faux_argv_t *srp_udata_path(kcontext_t *context);
void srp_udata_set_path(kcontext_t *context, faux_argv_t *path);
sr_session_ctx_t *srp_udata_sr_sess(kcontext_t *context);

// Private
enum diff_op {
    DIFF_OP_CREATE,
    DIFF_OP_DELETE,
    DIFF_OP_REPLACE,
    DIFF_OP_NONE,
};

bool_t show_xpath(sr_session_ctx_t *sess, const char *xpath, pline_opts_t *opts);
void show_subtree(const struct lyd_node *nodes_list, size_t level,
	enum diff_op op, pline_opts_t *opts, bool_t parent_is_oneliner);

// kly helper library
typedef struct {
	const struct lysc_node *node;
	const char *value;
	const char *dflt;
} klysc_key_t;
int klysc_key_compare(const void *first, const void *second);
int klysc_key_kcompare(const void *key, const void *list_item);

bool_t klysc_node_ext(const struct lysc_node *node,
	const char *module, const char *name, const char **argument);
bool_t klysc_node_ext_is_password(const struct lysc_node *node);
const char *klysc_node_ext_completion(const struct lysc_node *node);
const char *klysc_node_ext_default(const struct lysc_node *node);
char *klyd_node_value(const struct lyd_node *node);
const struct lysc_node *klysc_find_child(const struct lysc_node *node,
	const char *name);
char *klysc_leafref_xpath(const struct lysc_node *node,
	const struct lysc_type *type, const char *node_path);
const char *klysc_identityref_prefix(struct lysc_type_identityref *type,
	const char *name);
size_t klyd_visible_child_num(const struct lyd_node *node);
bool_t kly_str2ds(const char *str, size_t len, sr_datastore_t *ds);
bool_t kly_parse_ext_xpath(const char *xpath, const char **raw_xpath,
	sr_datastore_t *ds);

C_DECL_END


#endif // _plugin_sysrepo_private_h
