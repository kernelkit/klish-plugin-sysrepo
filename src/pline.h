/** @file pline.h
 * @brief Plain line.
 */

#ifndef _pline_h
#define _pline_h

#include <faux/list.h>
#include <faux/argv.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

// Type of positional pline argument
// P(line) A(rg) T(ype)
typedef enum {
	PAT_NONE			= 0x0001,
	PAT_CONTAINER			= 0x0002,
	PAT_LIST			= 0x0004,
	PAT_LIST_KEY			= 0x0008,
	PAT_LIST_KEY_INCOMPLETED	= 0x0010,
	PAT_LEAF			= 0x0020,
	PAT_LEAF_VALUE			= 0x0040,
	PAT_LEAFLIST			= 0x0080,
	PAT_LEAFLIST_VALUE		= 0x0100,
} pat_e;


// Type of pline expression
// P(line) T(ype)
typedef enum {

	PT_SET =
		PAT_CONTAINER |
		PAT_LIST_KEY |
		PAT_LEAF_VALUE |
		PAT_LEAFLIST_VALUE,

	PT_DEL =
		PAT_CONTAINER |
		PAT_LIST_KEY |
		PAT_LEAF |
		PAT_LEAFLIST |
		PAT_LEAFLIST_VALUE,

	PT_EDIT =
		PAT_CONTAINER |
		PAT_LIST_KEY,

} pt_e;


// Plain EXPRession
typedef struct {
	char *xpath;
	char *value;
	bool_t active;
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
} pcompl_t;


// Plain LINE
typedef struct pline_s {
	sr_session_ctx_t *sess;
	faux_list_t *exprs;
	faux_list_t *compls;
} pline_t;


C_DECL_BEGIN

pline_t *pline_new(sr_session_ctx_t *sess);
pline_t *pline_parse(sr_session_ctx_t *sess, faux_argv_t *argv, uint32_t flags);

void pline_free(pline_t *pline);

void pline_debug(pline_t *pline);
void pline_print_completions(const pline_t *pline, bool_t help);

C_DECL_END

#endif				/* _pline_h */