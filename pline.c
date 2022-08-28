/** @file pline.c
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <libyang/tree_edit.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/list.h>
#include <faux/argv.h>

#include "pline.h"

#define NODETYPE_CONF (LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST)


pexpr_t *pexpr_new(void)
{
	pexpr_t *pexpr = NULL;

	pexpr = faux_zmalloc(sizeof(*pexpr));
	assert(pexpr);
	if (!pexpr)
		return NULL;

	// Initialize
	pexpr->xpath = NULL;
	pexpr->value = NULL;
	pexpr->active = BOOL_FALSE;

	return pexpr;
}


void pexpr_free(pexpr_t *pexpr)
{
	if (!pexpr)
		return;

	faux_str_free(pexpr->xpath);
	faux_str_free(pexpr->value);

	free(pexpr);
}


pcompl_t *pcompl_new(void)
{
	pcompl_t *pcompl = NULL;

	pcompl = faux_zmalloc(sizeof(*pcompl));
	assert(pcompl);
	if (!pcompl)
		return NULL;

	// Initialize
	pcompl->type = PCOMPL_NODE;
	pcompl->node = NULL;
	pcompl->xpath = NULL;

	return pcompl;
}


void pcompl_free(pcompl_t *pcompl)
{
	if (!pcompl)
		return;

	faux_str_free(pcompl->xpath);

	free(pcompl);
}


pline_t *pline_new(void)
{
	pline_t *pline = NULL;

	pline = faux_zmalloc(sizeof(*pline));
	assert(pline);
	if (!pline)
		return NULL;

	// Init
	pline->exprs = faux_list_new(FAUX_LIST_UNSORTED, FAUX_LIST_NONUNIQUE,
		NULL, NULL, (faux_list_free_fn)pexpr_free);
	pline->compls = faux_list_new(FAUX_LIST_UNSORTED, FAUX_LIST_NONUNIQUE,
		NULL, NULL, (faux_list_free_fn)pcompl_free);

	return pline;
}


void pline_free(pline_t *pline)
{
	if (!pline)
		return;

	faux_list_free(pline->exprs);
	faux_list_free(pline->compls);

	faux_free(pline);
}

pexpr_t *pline_add_expr(pline_t *pline, const char *xpath)
{
	pexpr_t *pexpr = NULL;

	assert(pline);

	pexpr = pexpr_new();
	if (xpath)
		pexpr->xpath = faux_str_dup(xpath);
	faux_list_add(pline->exprs, pexpr);
}


pexpr_t *pline_current_expr(pline_t *pline)
{
	assert(pline);

	if (faux_list_len(pline->exprs) == 0)
		pline_add_expr(pline, NULL);

	return (pexpr_t *)faux_list_data(faux_list_tail(pline->exprs));
}


void pline_add_compl(pline_t *pline,
	pcompl_type_e type, const struct lysc_node *node, char *xpath)
{
	pcompl_t *pcompl = NULL;

	assert(pline);

	pcompl = pcompl_new();
	pcompl->type = type;
	pcompl->node = node;
	if (xpath)
		pcompl->xpath = faux_str_dup(xpath);
	faux_list_add(pline->compls, pcompl);
}


void pline_add_compl_subtree(pline_t *pline, const struct lys_module *module,
	const struct lysc_node *node)
{
	const struct lysc_node *subtree = NULL;
	const struct lysc_node *iter = NULL;

	assert(pline);
	assert(module);

	if (node)
		subtree = lysc_node_child(node);
	else
		subtree = module->compiled->data;

	LY_LIST_FOR(subtree, iter) {
		if (!(iter->nodetype & NODETYPE_CONF))
			continue;
		if (!(iter->flags & LYS_CONFIG_W))
			continue;
		pline_add_compl(pline, PCOMPL_NODE, iter, NULL);
	}
}


void pline_debug(pline_t *pline)
{
	faux_list_node_t *iter = NULL;
	pexpr_t *pexpr = NULL;
	pcompl_t *pcompl = NULL;

	printf("=== Expressions:\n\n");

	iter = faux_list_head(pline->exprs);
	while (pexpr = (pexpr_t *)faux_list_each(&iter)) {
		printf("pexpr.xpath = %s\n", pexpr->xpath ? pexpr->xpath : "NULL");
		printf("pexpr.value = %s\n", pexpr->value ? pexpr->value : "NULL");
		printf("pexpr.active = %s\n", pexpr->active ? "true" : "false");
		printf("\n");
	}

	printf("=== Completions:\n\n");

	iter = faux_list_head(pline->compls);
	while (pcompl = (pcompl_t *)faux_list_each(&iter)) {
		printf("pcompl.type = %s\n", (pcompl->type == PCOMPL_NODE) ?
			"PCOMPL_NODE" : "PCOMPL_TYPE");
		printf("pcompl.node = %s\n", pcompl->node ? pcompl->node->name : "NULL");
		printf("pcompl.xpath = %s\n", pcompl->xpath ? pcompl->xpath : "NULL");
		printf("\n");
	}
}


static int
sr_ly_module_is_internal(const struct lys_module *ly_mod);

int
sr_module_is_internal(const struct lys_module *ly_mod);


// Don't use standard lys_find_child() because it checks given module to be
// equal to found node's module. So augmented nodes will not be found.
static const struct lysc_node *find_child(const struct lysc_node *node,
	const char *name)
{
	const struct lysc_node *iter = NULL;

	if (!node)
		return NULL;

	LY_LIST_FOR(node, iter) {
		if (!(iter->nodetype & NODETYPE_CONF))
			continue;
		if (!(iter->flags & LYS_CONFIG_W))
			continue;
		if (!faux_str_cmp(iter->name, name))
			return iter;
	}

	return NULL;
}


static struct lysc_ident *find_ident(struct lysc_ident *ident, const char *name)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	if (!ident)
		return NULL;

	if (!ident->derived) {
		if (!faux_str_cmp(name, ident->name))
			return ident;
		return NULL;
	}

	LY_ARRAY_FOR(ident->derived, u) {
		struct lysc_ident *identity = find_ident(ident->derived[u], name);
		if (identity)
			return identity;
	}

	return NULL;
}


static const char *identityref_prefix(struct lysc_type_identityref *type,
	const char *name)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	assert(type);

	LY_ARRAY_FOR(type->bases, u) {
		struct lysc_ident *identity = find_ident(type->bases[u], name);
		if (identity)
			return identity->module->name;
	}

	return NULL;
}


bool_t pline_parse_module(const struct lys_module *module, faux_argv_t *argv,
	pline_t *pline)
{
	faux_argv_node_t *arg = faux_argv_iter(argv);
	const struct lysc_node *node = NULL;
	char *rollback_xpath = NULL;
	// Rollback is a mechanism to roll to previous node while
	// oneliners parsing
	bool_t rollback = BOOL_FALSE;

	do {
		pexpr_t *pexpr = pline_current_expr(pline);
		const char *str = (const char *)faux_argv_current(arg);
		bool_t is_rollback = rollback;
		bool_t next_arg = BOOL_TRUE;

		rollback = BOOL_FALSE;

		if (node && !is_rollback) {
			char *tmp = NULL;

			// Save rollback Xpath (for oneliners) before leaf node
			// Only leaf and leaf-list node allows to "rollback"
			// the path and add additional statements
			if (node->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
				faux_str_free(rollback_xpath);
				rollback_xpath = faux_str_dup(pexpr->xpath);
			}

			// Add current node to Xpath
			tmp = faux_str_sprintf("/%s:%s",
				node->module->name, node->name);
			faux_str_cat(&pexpr->xpath, tmp);
			faux_str_free(tmp);

			// Activate current expression. Because it really has
			// new component
			pexpr->active = BOOL_TRUE;
		}

		// Root of the module
		if (!node) {

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				return BOOL_FALSE;
			}

			// Next element
			node = find_child(module->compiled->data, str);
			if (!node)
				return BOOL_FALSE;

		// Container
		} else if (node->nodetype & LYS_CONTAINER) {

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = find_child(lysc_node_child(node), str);

		// List
		} else if (node->nodetype & LYS_LIST) {
			const struct lysc_node *iter = NULL;

			// Next element
			if (!is_rollback) {
				bool_t break_upper_loop = BOOL_FALSE;

				LY_LIST_FOR(lysc_node_child(node), iter) {
					char *tmp = NULL;
					struct lysc_node_leaf *leaf =
						(struct lysc_node_leaf *)iter;

					if (!(iter->nodetype & LYS_LEAF))
						continue;
					if (!(iter->flags & LYS_KEY))
						continue;
					assert (leaf->type->basetype != LY_TYPE_EMPTY);

					// Completion
					if (!str) {
						char *tmp = NULL;

						tmp = faux_str_sprintf("%s/%s",
							pexpr->xpath, leaf->name);
						pline_add_compl(pline,
							PCOMPL_TYPE, iter, tmp);
						faux_str_free(tmp);
						break_upper_loop = BOOL_TRUE;
						break;
					}

					tmp = faux_str_sprintf("[%s='%s']",
						leaf->name, str);
					faux_str_cat(&pexpr->xpath, tmp);
					faux_str_free(tmp);
					faux_argv_each(&arg);
					str = (const char *)faux_argv_current(arg);
				}
				if (break_upper_loop)
					break;
			}

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = find_child(lysc_node_child(node), str);

		// Leaf
		} else if (node->nodetype & LYS_LEAF) {
			struct lysc_node_leaf *leaf =
				(struct lysc_node_leaf *)node;

			// Next element
			if (LY_TYPE_EMPTY == leaf->type->basetype) {
				// Completion
				if (!str) {
					pline_add_compl_subtree(pline,
						module, node->parent);
					break;
				}
				// Don't get next argument when argument is not
				// really consumed
				next_arg = BOOL_FALSE;
			} else {
				// Completion
				if (!str) {
					pline_add_compl(pline,
						PCOMPL_TYPE, node, NULL);
					break;
				}
				// Idenity must have prefix
				if (LY_TYPE_IDENT == leaf->type->basetype) {
					const char *prefix = NULL;
					prefix = identityref_prefix(
						(struct lysc_type_identityref *)
						leaf->type, str);
					if (prefix)
						pexpr->value = faux_str_sprintf(
							"%s:", prefix);
				}
				faux_str_cat(&pexpr->value, str);
			}
			// Expression was completed
			// So rollback (for oneliners)
			node = node->parent;
			pline_add_expr(pline, rollback_xpath);
			rollback = BOOL_TRUE;

		// Leaf-list
		} else if (node->nodetype & LYS_LEAFLIST) {
			char *tmp = NULL;
			const char *prefix = NULL;
			struct lysc_node_leaflist *leaflist =
				(struct lysc_node_leaflist *)node;

			// Completion
			if (!str) {
				pline_add_compl(pline,
					PCOMPL_TYPE, node, pexpr->xpath);
				break;
			}

			// Idenity must have prefix
			if (LY_TYPE_IDENT == leaflist->type->basetype) {
				prefix = identityref_prefix(
					(struct lysc_type_identityref *)
					leaflist->type, str);
			}

			tmp = faux_str_sprintf("[.='%s%s%s']",
			prefix ? prefix : "", prefix ? ":" : "", str);
			faux_str_cat(&pexpr->xpath, tmp);
			faux_str_free(tmp);

			// Expression was completed
			// So rollback (for oneliners)
			node = node->parent;
			pline_add_expr(pline, rollback_xpath);
			rollback = BOOL_TRUE;
		}

		if (next_arg)
			faux_argv_each(&arg);
	} while (node || rollback);

	faux_str_free(rollback_xpath);

	return BOOL_TRUE;
}


pline_t *pline_parse(const struct ly_ctx *ctx, faux_argv_t *argv, uint32_t flags)
{
	struct lys_module *module = NULL;
	pline_t *pline = pline_new();
	uint32_t i = 0;

	assert(ctx);
	if (!ctx)
		return NULL;

	// Iterate all modules
	i = 0;
	while ((module = ly_ctx_get_module_iter(ctx, &i))) {
		if (sr_module_is_internal(module))
			continue;
		if (!module->compiled)
			continue;
		if (!module->implemented)
			continue;
		if (!module->compiled->data)
			continue;
		if (pline_parse_module(module, argv, pline))
			break; // Found
	}

	return pline;
}


static void identityref(struct lysc_ident *ident)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	if (!ident)
		return;

	if (!ident->derived) {
		printf("%s\n", ident->name);
		return;
	}

	LY_ARRAY_FOR(ident->derived, u) {
		identityref(ident->derived[u]);
	}
}


void pline_print_type_completions(const struct lysc_type *type)
{
	assert(type);

	switch (type->basetype) {

	case LY_TYPE_BOOL: {
		printf("true\nfalse\n");
		break;
	}

	case LY_TYPE_ENUM: {
		const struct lysc_type_enum *t =
			(const struct lysc_type_enum *)type;
		LY_ARRAY_COUNT_TYPE u = 0;

		LY_ARRAY_FOR(t->enums, u) {
			printf("%s\n",t->enums[u].name);
		}
		break;
	}

	case LY_TYPE_IDENT: {
		struct lysc_type_identityref *t =
			(struct lysc_type_identityref *)type;
		LY_ARRAY_COUNT_TYPE u = 0;

		LY_ARRAY_FOR(t->bases, u) {
			identityref(t->bases[u]);
		}
		break;
	}

	case LY_TYPE_UNION: {
		struct lysc_type_union *t =
			(struct lysc_type_union *)type;
		LY_ARRAY_COUNT_TYPE u = 0;

		LY_ARRAY_FOR(t->types, u) {
			pline_print_type_completions(t->types[u]);
		}
		break;
	}

	default:
		break;
	}
}


void pline_print_completions(const pline_t *pline)
{
	faux_list_node_t *iter = NULL;
	pcompl_t *pcompl = NULL;

	iter = faux_list_head(pline->compls);
	while (pcompl = (pcompl_t *)faux_list_each(&iter)) {
		struct lysc_type *type = NULL;
		const struct lysc_node *node = pcompl->node;

//		printf("pcompl.xpath = %s\n", pcompl->xpath ? pcompl->xpath : "NULL");

		if (!node)
			continue;

		// Node
		if (PCOMPL_NODE == pcompl->type) {
			printf("%s\n", node->name);
			continue;
		}

		// Type
		if (node->nodetype & LYS_LEAF)
			type = ((struct lysc_node_leaf *)node)->type;
		else if (node->nodetype & LYS_LEAFLIST)
			type = ((struct lysc_node_leaflist *)node)->type;
		else
			continue;
		pline_print_type_completions(type);
	}
}
