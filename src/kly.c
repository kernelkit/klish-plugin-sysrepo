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
