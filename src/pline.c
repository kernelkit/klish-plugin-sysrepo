/** @file pline.c
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <faux/faux.h>
#include <faux/str.h>
#include <faux/list.h>
#include <faux/argv.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>
#include <libyang/tree_edit.h>

#include "private.h"
#include "pline.h"


static pexpr_t *pexpr_new(void)
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
	pexpr->pat = PAT_NONE;
	pexpr->args_num = 0;
	pexpr->list_pos = 0;
	pexpr->last_keys = NULL;

	return pexpr;
}


static void pexpr_free(pexpr_t *pexpr)
{
	if (!pexpr)
		return;

	faux_str_free(pexpr->xpath);
	faux_str_free(pexpr->value);
	faux_str_free(pexpr->last_keys);

	free(pexpr);
}


static pcompl_t *pcompl_new(void)
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


static void pcompl_free(pcompl_t *pcompl)
{
	if (!pcompl)
		return;

	faux_str_free(pcompl->xpath);

	free(pcompl);
}


pline_t *pline_new(sr_session_ctx_t *sess)
{
	pline_t *pline = NULL;

	pline = faux_zmalloc(sizeof(*pline));
	assert(pline);
	if (!pline)
		return NULL;

	// Init
	pline->sess = sess;
	pline->invalid = BOOL_FALSE;
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

static pexpr_t *pline_add_expr(pline_t *pline, const char *xpath,
	size_t args_num, size_t list_pos)
{
	pexpr_t *pexpr = NULL;

	assert(pline);

	pexpr = pexpr_new();
	if (xpath)
		pexpr->xpath = faux_str_dup(xpath);
	pexpr->args_num = args_num;
	pexpr->list_pos = list_pos;
	faux_list_add(pline->exprs, pexpr);

	return pexpr;
}


pexpr_t *pline_current_expr(pline_t *pline)
{
	assert(pline);

	if (faux_list_len(pline->exprs) == 0)
		pline_add_expr(pline, NULL, 0, 0);

	return (pexpr_t *)faux_list_data(faux_list_tail(pline->exprs));
}


static void pline_add_compl(pline_t *pline,
	pcompl_type_e type, const struct lysc_node *node, const char *xpath)
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


static void pline_add_compl_subtree(pline_t *pline, const struct lys_module *module,
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
		if (!(iter->nodetype & SRP_NODETYPE_CONF))
			continue;
		if (!(iter->flags & LYS_CONFIG_W))
			continue;
		if ((iter->nodetype & LYS_LEAF) && (iter->flags & LYS_KEY))
			continue;
		if (iter->nodetype & (LYS_CHOICE | LYS_CASE)) {
			pline_add_compl_subtree(pline, module, iter);
			continue;
		}
		pline_add_compl(pline, PCOMPL_NODE, iter, NULL);
	}
}


void pline_debug(pline_t *pline)
{
	faux_list_node_t *iter = NULL;
	pexpr_t *pexpr = NULL;
	pcompl_t *pcompl = NULL;

	printf("====== Pline:\n\n");

	printf("invalid = %s\n", pline->invalid ? "true" : "false");
	printf("\n");

	printf("=== Expressions:\n\n");

	iter = faux_list_head(pline->exprs);
	while ((pexpr = (pexpr_t *)faux_list_each(&iter))) {
		char *pat = NULL;
		printf("pexpr.xpath = %s\n", pexpr->xpath ? pexpr->xpath : "NULL");
		printf("pexpr.value = %s\n", pexpr->value ? pexpr->value : "NULL");
		printf("pexpr.active = %s\n", pexpr->active ? "true" : "false");
		switch (pexpr->pat) {
		case 0x0001:
			pat = "NONE";
			break;
		case 0x0002:
			pat = "CONTAINER";
			break;
		case 0x0004:
			pat = "LIST";
			break;
		case 0x0008:
			pat = "LIST_KEY";
			break;
		case 0x0010:
			pat = "LIST_KEY_INCOMPLETED";
			break;
		case 0x0020:
			pat = "LEAF";
			break;
		case 0x0040:
			pat = "LEAF_VALUE";
			break;
		case 0x0080:
			pat = "LEAF_EMPTY";
			break;
		case 0x0100:
			pat = "LEAFLIST";
			break;
		case 0x0200:
			pat = "LEAFLIST_VALUE";
			break;
		default:
			pat = "UNKNOWN";
			break;
		}
		printf("pexpr.pat = %s\n", pat);
		printf("pexpr.args_num = %lu\n", pexpr->args_num);
		printf("pexpr.list_pos = %lu\n", pexpr->list_pos);
		printf("pexpr.last_keys = %s\n", pexpr->last_keys ? pexpr->last_keys : "NULL");
		printf("\n");
	}

	printf("=== Completions:\n\n");

	iter = faux_list_head(pline->compls);
	while ((pcompl = (pcompl_t *)faux_list_each(&iter))) {
		printf("pcompl.type = %s\n", (pcompl->type == PCOMPL_NODE) ?
			"PCOMPL_NODE" : "PCOMPL_TYPE");
		printf("pcompl.node = %s\n", pcompl->node ? pcompl->node->name : "NULL");
		printf("pcompl.xpath = %s\n", pcompl->xpath ? pcompl->xpath : "NULL");
		printf("\n");
	}
}


static bool_t pline_parse_module(const struct lys_module *module, faux_argv_t *argv,
	pline_t *pline, pline_opts_t *opts)
{
	faux_argv_node_t *arg = faux_argv_iter(argv);
	const struct lysc_node *node = NULL;
	char *rollback_xpath = NULL;
	size_t rollback_args_num = 0;
	size_t rollback_list_pos = 0;
	// Rollback is a mechanism to roll to previous node while
	// oneliners parsing
	bool_t rollback = BOOL_FALSE;
	pexpr_t *first_pexpr = NULL;

	// It's necessary because upper function can use the same pline object
	// for another modules before. It uses the same object to collect
	// possible completions. But pline is really invalid only when all
	// modules don't recognize argument.
	pline->invalid = BOOL_FALSE;

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
				rollback_args_num = pexpr->args_num;
				rollback_list_pos = pexpr->list_pos;
			}

			// Add current node to Xpath
			tmp = faux_str_sprintf("/%s:%s",
				node->module->name, node->name);
			faux_str_cat(&pexpr->xpath, tmp);
			faux_str_free(tmp);
			pexpr->args_num++;

			// Activate current expression. Because it really has
			// new component
			pexpr->active = BOOL_TRUE;
		}

		// Root of the module
		if (!node) {

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = klysc_find_child(module->compiled->data, str);
			if (!node)
				break;

		// Container
		} else if (node->nodetype & LYS_CONTAINER) {

			pexpr->pat = PAT_CONTAINER;

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = klysc_find_child(lysc_node_child(node), str);

		// List
		} else if (node->nodetype & LYS_LIST) {
			const struct lysc_node *iter = NULL;

			pexpr->pat = PAT_LIST;
			pexpr->list_pos = pexpr->args_num;
			faux_str_free(pexpr->last_keys);
			pexpr->last_keys = NULL;

			// Next element
			if (!is_rollback) {
				bool_t break_upper_loop = BOOL_FALSE;

				// Keys without statement. Positional parameters.
				if (!opts->keys_w_stmt) {

					LY_LIST_FOR(lysc_node_child(node), iter) {
						char *tmp = NULL;
						char *escaped = NULL;
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
							char *compl_xpath = NULL;

							tmp = faux_str_sprintf("%s/%s",
								pexpr->xpath, leaf->name);
							pline_add_compl(pline,
								PCOMPL_TYPE, iter, tmp);
							compl_xpath = klysc_leafref_xpath(iter, tmp);
							if (compl_xpath) {
								pline_add_compl(pline, PCOMPL_TYPE,
									NULL, compl_xpath);
								faux_str_free(compl_xpath);
							}
							faux_str_free(tmp);
							break_upper_loop = BOOL_TRUE;
							break;
						}

						escaped = faux_str_c_esc(str);
						tmp = faux_str_sprintf("[%s=\"%s\"]",
							leaf->name, escaped);
						faux_str_free(escaped);
						faux_str_cat(&pexpr->xpath, tmp);
						faux_str_cat(&pexpr->last_keys, tmp);
						faux_str_free(tmp);
						pexpr->args_num++;
						faux_argv_each(&arg);
						str = (const char *)faux_argv_current(arg);
						pexpr->pat = PAT_LIST_KEY_INCOMPLETED;
					}

				// Keys with statements. Arbitrary order of keys.
				} else {
					faux_list_t *keys = NULL;
					unsigned int specified_keys_num = 0;
					klysc_key_t *cur_key = NULL;
					bool_t first_key = BOOL_TRUE;
					bool_t first_key_is_optional = BOOL_FALSE;
					faux_list_node_t *key_iter = NULL;

					// List keys
					keys = faux_list_new(FAUX_LIST_UNSORTED,
						FAUX_LIST_UNIQUE,
						klysc_key_compare,
						klysc_key_kcompare,
						(faux_list_free_fn)faux_free);

					LY_LIST_FOR(lysc_node_child(node), iter) {
						struct lysc_node_leaf *leaf =
							(struct lysc_node_leaf *)iter;
						klysc_key_t *key = NULL;

						if (!(iter->nodetype & LYS_LEAF))
							continue;
						if (!(iter->flags & LYS_KEY))
							continue;
						assert (leaf->type->basetype != LY_TYPE_EMPTY);
						key = faux_zmalloc(sizeof(*key));
						assert(key);
						key->node = iter;
						if (opts->default_keys &&
							(key->dflt = klysc_node_ext_default(iter))) {
							if (first_key)
								first_key_is_optional = BOOL_TRUE;
						}
						faux_list_add(keys, key);
						first_key = BOOL_FALSE;
					}

					while (specified_keys_num < faux_list_len(keys)) {
						char *tmp = NULL;
						char *escaped = NULL;

						// First key without statement. Must be mandatory.
						if ((0 == specified_keys_num) &&
							!opts->first_key_w_stmt &&
							!first_key_is_optional) {
							cur_key = (klysc_key_t *)faux_list_data(faux_list_head(keys));
						} else {
							if (!str)
								break;
							cur_key = faux_list_kfind(keys, str);
							if (!cur_key || cur_key->value)
								break;
							pexpr->args_num++;
							faux_argv_each(&arg);
							str = (const char *)faux_argv_current(arg);
						}
						pexpr->pat = PAT_LIST_KEY_INCOMPLETED;

						// Completion
						if (!str) {
							char *tmp = NULL;
							char *compl_xpath = NULL;

							tmp = faux_str_sprintf("%s/%s",
								pexpr->xpath, cur_key->node->name);
							pline_add_compl(pline,
								PCOMPL_TYPE, cur_key->node, tmp);
							compl_xpath = klysc_leafref_xpath(iter, tmp);
							if (compl_xpath) {
								pline_add_compl(pline, PCOMPL_TYPE,
									NULL, compl_xpath);
								faux_str_free(compl_xpath);
							}
							faux_str_free(tmp);
							break_upper_loop = BOOL_TRUE;
							break;
						}

						escaped = faux_str_c_esc(str);
						tmp = faux_str_sprintf("[%s=\"%s\"]",
							cur_key->node->name, escaped);
						faux_str_free(escaped);
						faux_str_cat(&pexpr->xpath, tmp);
						faux_str_cat(&pexpr->last_keys, tmp);
						faux_str_free(tmp);
						cur_key->value = str;
						specified_keys_num++;
						pexpr->args_num++;
						faux_argv_each(&arg);
						str = (const char *)faux_argv_current(arg);
						pexpr->pat = PAT_LIST_KEY_INCOMPLETED;
					}
					if (break_upper_loop) {
						faux_list_free(keys);
						break;
					}

					key_iter = faux_list_head(keys);
					while((cur_key = (klysc_key_t *)faux_list_each(&key_iter))) {
						if (cur_key->value)
							continue;

						// Completion
						if (!str) {
//							if ((0 == specified_keys_num) &&
//								!opts->first_key_w_stmt &&
//								!first_key_is_optional) {
							pline_add_compl(pline,
								PCOMPL_NODE, cur_key->node, NULL);
						}

						if (opts->default_keys && cur_key->dflt) {
							char *tmp = NULL;
							char *escaped = NULL;

							escaped = faux_str_c_esc(cur_key->dflt);
							tmp = faux_str_sprintf("[%s=\"%s\"]",
								cur_key->node->name, escaped);
							faux_str_free(escaped);
							faux_str_cat(&pexpr->xpath, tmp);
							faux_str_cat(&pexpr->last_keys, tmp);
							faux_str_free(tmp);
							pexpr->pat = PAT_LIST_KEY_INCOMPLETED;
						} else { // Mandatory key is not specified
							break_upper_loop = BOOL_TRUE;
						}
					}
					faux_list_free(keys);
				}
				if (break_upper_loop)
					break;
			}

			pexpr->pat = PAT_LIST_KEY;

 			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = klysc_find_child(lysc_node_child(node), str);

		// Leaf
		} else if (node->nodetype & LYS_LEAF) {
			struct lysc_node_leaf *leaf =
				(struct lysc_node_leaf *)node;

			// Next element
			if (LY_TYPE_EMPTY == leaf->type->basetype) {

				pexpr->pat = PAT_LEAF_EMPTY;

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

				pexpr->pat = PAT_LEAF;

				// Completion
				if (!str) {
					char *compl_xpath = klysc_leafref_xpath(node, pexpr->xpath);
					pline_add_compl(pline,
						PCOMPL_TYPE, node, compl_xpath);
					faux_str_free(compl_xpath);
					break;
				}

				pexpr->pat = PAT_LEAF_VALUE;

				// Idenity must have prefix
				if (LY_TYPE_IDENT == leaf->type->basetype) {
					const char *prefix = NULL;
					prefix = klysc_identityref_prefix(
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
			pline_add_expr(pline, rollback_xpath,
				rollback_args_num, rollback_list_pos);
			rollback = BOOL_TRUE;

		// Leaf-list
		} else if (node->nodetype & LYS_LEAFLIST) {
			char *tmp = NULL;
			const char *prefix = NULL;
			struct lysc_node_leaflist *leaflist =
				(struct lysc_node_leaflist *)node;

			pexpr->pat = PAT_LEAFLIST;
			pexpr->list_pos = pexpr->args_num;
			faux_str_free(pexpr->last_keys);
			pexpr->last_keys = NULL;

			// Completion
			if (!str) {
				char *compl_xpath = klysc_leafref_xpath(node, pexpr->xpath);

				if (compl_xpath) {
					pline_add_compl(pline,
						PCOMPL_TYPE, NULL, compl_xpath);
					faux_str_free(compl_xpath);
				}
				pline_add_compl(pline,
					PCOMPL_TYPE, node, pexpr->xpath);
				break;
			}

			pexpr->pat = PAT_LEAFLIST_VALUE;

			// Idenity must have prefix
			if (LY_TYPE_IDENT == leaflist->type->basetype) {
				prefix = klysc_identityref_prefix(
					(struct lysc_type_identityref *)
					leaflist->type, str);
			}

			tmp = faux_str_sprintf("[.='%s%s%s']",
			prefix ? prefix : "", prefix ? ":" : "", str);
			faux_str_cat(&pexpr->xpath, tmp);
			faux_str_cat(&pexpr->last_keys, str);
			faux_str_free(tmp);
			pexpr->args_num++;

			// Expression was completed
			// So rollback (for oneliners)
			node = node->parent;
			pline_add_expr(pline, rollback_xpath,
				rollback_args_num, rollback_list_pos);
			rollback = BOOL_TRUE;

		// LYS_CHOICE and LYS_CASE can appear while rollback only
		} else if (node->nodetype & (LYS_CHOICE | LYS_CASE)) {

			// Don't set pexpr->pat because CHOICE and CASE can't
			// appear within data tree (schema only)

			// Completion
			if (!str) {
				pline_add_compl_subtree(pline, module, node);
				break;
			}

			// Next element
			node = klysc_find_child(lysc_node_child(node), str);

		} else {
			break;
		}

		// Current argument was not consumed.
		// Break before getting next arg.
		if (!node && !rollback)
			break;

		if (next_arg)
			faux_argv_each(&arg);
	} while (BOOL_TRUE);

	// There is not-consumed argument so whole pline is invalid
	if (faux_argv_current(arg))
		pline->invalid = BOOL_TRUE;

	faux_str_free(rollback_xpath);

	first_pexpr = (pexpr_t *)faux_list_data(faux_list_head(pline->exprs));
	if (!first_pexpr || !first_pexpr->xpath)
		return BOOL_FALSE; // Not found

	return BOOL_TRUE;
}


pline_t *pline_parse(sr_session_ctx_t *sess, faux_argv_t *argv, pline_opts_t *opts)
{
	const struct ly_ctx *ctx = NULL;
	struct lys_module *module = NULL;
	pline_t *pline = NULL;
	uint32_t i = 0;
	faux_list_node_t *last_expr_node = NULL;

	assert(sess);
	if (!sess)
		return NULL;

	pline = pline_new(sess);
	if (!pline)
		return NULL;
	ctx = sr_session_acquire_context(pline->sess);
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
		if (pline_parse_module(module, argv, pline, opts))
			break; // Found
	}

	sr_session_release_context(pline->sess);

	// Last parsed expression can be inactive so remove it from list
	last_expr_node = faux_list_tail(pline->exprs);
	if (last_expr_node) {
		pexpr_t *expr = (pexpr_t *)faux_list_data(last_expr_node);
		if (!expr->active)
			faux_list_del(pline->exprs, last_expr_node);
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


static void pline_print_type_completions(const struct lysc_type *type)
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


static void pline_print_type_help(const struct lysc_node *node,
	const struct lysc_type *type)
{
	assert(type);

	if ((type->basetype != LY_TYPE_UNION) &&
		(type->basetype != LY_TYPE_LEAFREF))
		printf("%s\n", node->name);

	switch (type->basetype) {

	case LY_TYPE_UINT8: {
		printf("Unsigned integer 8bit\n");
		break;
	}

	case LY_TYPE_UINT16: {
		printf("Unsigned integer 16bit\n");
		break;
	}

	case LY_TYPE_UINT32: {
		printf("Unsigned integer 32bit\n");
		break;
	}

	case LY_TYPE_UINT64: {
		printf("Unsigned integer 64bit\n");
		break;
	}

	case LY_TYPE_INT8: {
		printf("Integer 8bit\n");
		break;
	}

	case LY_TYPE_INT16: {
		printf("Integer 16bit\n");
		break;
	}

	case LY_TYPE_INT32: {
		printf("Integer 32bit\n");
		break;
	}

	case LY_TYPE_INT64: {
		printf("Integer 64bit\n");
		break;
	}

	case LY_TYPE_STRING: {
		printf("String\n");
		break;
	}

	case LY_TYPE_BOOL: {
		printf("Boolean true/false\n");
		break;
	}

	case LY_TYPE_DEC64: {
		printf("Signed decimal number\n");
		break;
	}

	case LY_TYPE_ENUM: {
		printf("Enumerated choice\n");
		break;
	}

	case LY_TYPE_IDENT: {
		printf("Identity\n");
		break;
	}

	case LY_TYPE_UNION: {
		struct lysc_type_union *t =
			(struct lysc_type_union *)type;
		LY_ARRAY_COUNT_TYPE u = 0;

		LY_ARRAY_FOR(t->types, u) {
			pline_print_type_help(node, t->types[u]);
		}
		break;
	}

	case LY_TYPE_LEAFREF: {
		struct lysc_type_leafref *t =
			(struct lysc_type_leafref *)type;
		pline_print_type_help(node, t->realtype);
		}
		break;

	default:
		printf("Unknown\n");
		break;
	}
}


void pline_print_completions(const pline_t *pline, bool_t help)
{
	faux_list_node_t *iter = NULL;
	pcompl_t *pcompl = NULL;

	iter = faux_list_head(pline->compls);
	while ((pcompl = (pcompl_t *)faux_list_each(&iter))) {
		struct lysc_type *type = NULL;
		const struct lysc_node *node = pcompl->node;

		if (pcompl->xpath && !help) {
			sr_val_t *vals = NULL;
			size_t val_num = 0;
			size_t i = 0;

//printf("%s\n", pcompl->xpath);
			sr_get_items(pline->sess, pcompl->xpath,
				0, 0, &vals, &val_num);
			for (i = 0; i < val_num; i++) {
				char *tmp = sr_val_to_str(&vals[i]);
				if (!tmp)
					continue;
				printf("%s\n", tmp);
				free(tmp);
			}
			sr_free_values(vals, val_num);
		}

		if (!node)
			continue;

		// Node
		if (PCOMPL_NODE == pcompl->type) {
			printf("%s\n", node->name);
			if (help) {
				if (!node->dsc) {
					printf("%s\n", node->name);
				} else {
					char *dsc = faux_str_getline(node->dsc,
						NULL);
					printf("%s\n", dsc);
					faux_str_free(dsc);
				}
			}
			continue;
		}

		// Type
		if (node->nodetype & LYS_LEAF)
			type = ((struct lysc_node_leaf *)node)->type;
		else if (node->nodetype & LYS_LEAFLIST)
			type = ((struct lysc_node_leaflist *)node)->type;
		else
			continue;
		if (help)
			pline_print_type_help(node, type);
		else
			pline_print_type_completions(type);
	}
}
