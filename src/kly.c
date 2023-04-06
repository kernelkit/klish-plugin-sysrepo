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


int klysc_key_compare(const void *first, const void *second)
{
	const klysc_key_t *f = (const klysc_key_t *)first;
	const klysc_key_t *s = (const klysc_key_t *)second;

	return strcmp(f->node->name, s->node->name);
}


int klysc_key_kcompare(const void *key, const void *list_item)
{
	const char *f = (const char *)key;
	const klysc_key_t *s = (const klysc_key_t *)list_item;

	return strcmp(f, s->node->name);
}


// Get extension by name from schema node
static bool_t klysc_ext(const struct lysc_ext_instance *exts,
	const char *module, const char *name, const char **argument)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	if (!exts)
		return BOOL_FALSE;

	LY_ARRAY_FOR(exts, u) {
		const struct lysc_ext_instance *ext = &exts[u];
		//syslog(LOG_ERR, "mod: %s, ext: %s", ext->def->module->name, ext->def->name);
		if (faux_str_cmp(ext->def->module->name, module) != 0)
			continue;
		if (faux_str_cmp(ext->def->name, name) != 0)
			continue;
		if (argument)
			*argument = ext->argument;
		return BOOL_TRUE;
	}

	return BOOL_FALSE;
}


// Get extension by name
bool_t klysc_node_ext(const struct lysc_node *node,
	const char *module, const char *name, const char **argument)
{
	if (!node)
		return BOOL_FALSE;
	if (klysc_ext(node->exts, module, name, argument))
		return BOOL_TRUE;

	return BOOL_FALSE;
}


bool_t klysc_node_ext_is_password(const struct lysc_node *node)
{
	return klysc_node_ext(node, "klish", "password", NULL);
}


const char *klysc_node_ext_completion(const struct lysc_node *node)
{
	const char *xpath = NULL;

	klysc_node_ext(node, "klish", "completion", &xpath);

	return xpath;
}


const char *klysc_node_ext_default(const struct lysc_node *node)
{
	const char *dflt = NULL;

	klysc_node_ext(node, "klish", "default", &dflt);

	return dflt;
}


// Get value from data lyd node
char *klyd_node_value(const struct lyd_node *node)
{
	const struct lysc_node *schema = NULL;
	const struct lysc_type *type = NULL;
	const char *origin_value = NULL;
	char *space = NULL;
	char *escaped = NULL;
	char *result = NULL;

	if (!node)
		return NULL;

	schema = node->schema;
	if (!(schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)))
		return NULL;

	if (schema->nodetype & LYS_LEAF)
		type = ((const struct lysc_node_leaf *)schema)->type;
	else
		type = ((const struct lysc_node_leaflist *)schema)->type;

	if (type->basetype != LY_TYPE_IDENT) {
		origin_value = lyd_get_value(node);
	} else {
		// Identity
		const struct lyd_value *value = NULL;
		value = &((const struct lyd_node_term *)node)->value;
		origin_value = value->ident->name;
	}

	escaped = faux_str_c_esc(origin_value);
	// String with space must have quotes
	space = strchr(origin_value, ' ');
	if (space) {
		result = faux_str_sprintf("\"%s\"", escaped);
		faux_str_free(escaped);
	} else {
		result = escaped;
	}

	return result;
}


// Don't use standard lys_find_child() because it checks given module to be
// equal to found node's module. So augmented nodes will not be found.
const struct lysc_node *klysc_find_child(const struct lysc_node *node,
	const char *name)
{
	const struct lysc_node *iter = NULL;

	if (!node)
		return NULL;

	LY_LIST_FOR(node, iter) {
		if (!(iter->nodetype & SRP_NODETYPE_CONF))
			continue;
		if (!(iter->flags & LYS_CONFIG_W))
			continue;
		// Special case. LYS_CHOICE and LYS_CASE must search for
		// specified name inside themselfs.
		if (iter->nodetype & (LYS_CHOICE | LYS_CASE)) {
			const struct lysc_node *node_in = NULL;
			node_in = klysc_find_child(lysc_node_child(iter), name);
			if (node_in)
				return node_in;
			continue;
		}
		if (!faux_str_cmp(iter->name, name))
			return iter;
	}

	return NULL;
}


struct lysc_ident *klysc_find_ident(struct lysc_ident *ident, const char *name)
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
		struct lysc_ident *identity = klysc_find_ident(ident->derived[u], name);
		if (identity)
			return identity;
	}

	return NULL;
}
