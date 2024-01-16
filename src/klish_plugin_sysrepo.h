#ifndef _klish_pligin_sysrepo_h
#define _klish_plugin_sysrepo_h

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <faux/faux.h>
#include <faux/argv.h>
#include <faux/list.h>
#include <klish/kcontext_base.h>


// Type of positional pline argument
// P(line) A(rg) T(ype)
typedef enum {
	PAT_NONE			= 0x0000,
	PAT_CONTAINER			= 0x0001,
	PAT_LIST			= 0x0002,
	PAT_LIST_KEY			= 0x0004,
	PAT_LIST_KEY_INCOMPLETED	= 0x0008,
	PAT_LEAF			= 0x0010,
	PAT_LEAF_VALUE			= 0x0020,
	PAT_LEAF_EMPTY			= 0x0040,
	PAT_LEAFLIST			= 0x0080,
	PAT_LEAFLIST_VALUE		= 0x0100,
} pat_e;


// Type of pline expression
// P(line) T(ype)
typedef enum {

	PT_COMPL_ALL =
		PAT_CONTAINER |
		PAT_LIST |
		PAT_LIST_KEY |
		PAT_LIST_KEY_INCOMPLETED |
		PAT_LEAF |
		PAT_LEAF_VALUE |
		PAT_LEAF_EMPTY |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_SET =
		PAT_CONTAINER |
		PAT_LIST_KEY |
		PAT_LEAF_VALUE |
		PAT_LEAF_EMPTY |
		PAT_LEAFLIST_VALUE,

	PT_NOT_SET =
		0,

	PT_COMPL_SET =
		PAT_CONTAINER |
		PAT_LIST |
		PAT_LIST_KEY |
		PAT_LIST_KEY_INCOMPLETED |
		PAT_LEAF |
		PAT_LEAF_VALUE |
		PAT_LEAF_EMPTY |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_DEL =
		PAT_CONTAINER |
		PAT_LIST_KEY |
		PAT_LEAF |
		PAT_LEAF_EMPTY |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_NOT_DEL =
		PAT_LEAF_VALUE,

	PT_COMPL_DEL =
		PAT_CONTAINER |
		PAT_LIST |
		PAT_LIST_KEY |
		PAT_LIST_KEY_INCOMPLETED |
		PAT_LEAF |
		PAT_LEAF_EMPTY |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_EDIT =
		PAT_CONTAINER |
		PAT_LIST_KEY,

	PT_NOT_EDIT =
		PAT_LEAF |
		PAT_LEAF_VALUE |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_COMPL_EDIT =
		PAT_CONTAINER |
		PAT_LIST |
		PAT_LIST_KEY |
		PAT_LIST_KEY_INCOMPLETED,

	PT_INSERT =
		PAT_LIST_KEY |
		PAT_LEAFLIST_VALUE,

	PT_NOT_INSERT =
		PAT_LEAF |
		PAT_LEAF_VALUE,

	PT_COMPL_INSERT =
		PAT_CONTAINER |
		PAT_LIST |
		PAT_LIST_KEY |
		PAT_LIST_KEY_INCOMPLETED |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

} pt_e;


// Plain EXPRession
typedef struct {
	char *xpath;
	char *value;
	bool_t active;
	pat_e pat;
	size_t args_num;
	size_t list_pos;
	char *last_keys;
	size_t tree_depth;
} pexpr_t;


// Possible types of completion source
typedef enum {
	PCOMPL_NODE = 0,
	PCOMPL_TYPE = 1,
} pcompl_type_e;


// Plain COMPLetion
typedef struct {
	pcompl_type_e type;
	const struct lysc_node *node;
	char *xpath;
	sr_datastore_t xpath_ds;
	pat_e pat;
} pcompl_t;


// Plain LINE
typedef struct pline_s {
	sr_session_ctx_t *sess;
	bool_t invalid;
	faux_list_t *exprs;
	faux_list_t *compls;
} pline_t;


// Parse/show settings
typedef struct {
	char begin_bracket;
	char end_bracket;
	bool_t show_brackets;
	bool_t show_semicolons;
	bool_t first_key_w_stmt;
	bool_t keys_w_stmt;
	bool_t colorize;
	uint8_t indent;
	bool_t default_keys;
	bool_t show_default_keys;
	bool_t hide_passwords;
	bool_t enable_nacm;
	bool_t oneliners;
} pline_opts_t;


#define SRP_NODETYPE_CONF (LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST | LYS_CHOICE | LYS_CASE)


C_DECL_BEGIN

// PLine
pline_t *pline_new(sr_session_ctx_t *sess);
void pline_opts_init(pline_opts_t *opts);
int pline_opts_parse(const char *conf, pline_opts_t *opts);
int pline_opts_parse_file(const char *conf_name, pline_opts_t *opts);
pline_t *pline_parse(sr_session_ctx_t *sess, const faux_argv_t *argv,
	const pline_opts_t *opts);
pexpr_t *pline_current_expr(pline_t *pline);

void pline_free(pline_t *pline);

void pline_debug(pline_t *pline);
void pline_print_completions(const pline_t *pline, bool_t help,
	pt_e enabled_types, bool_t existing_nodes_only);

size_t num_of_keys(const struct lysc_node *node);

C_DECL_END


// Name of named klish's udata
#define SRP_UDATA_NAME "sysrepo"

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

// Service functions
int srp_mass_set(int fd, sr_datastore_t ds, const faux_argv_t *cur_path,
	const pline_opts_t *opts, const char *user, bool_t stop_on_error);

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


#endif // _klish_plugin_sysrepo_h
