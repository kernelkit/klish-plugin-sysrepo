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

#include "klish_plugin_sysrepo.h"


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


// Get extension by name from node
bool_t klysc_node_ext(const struct lysc_node *node,
	const char *module, const char *name, const char **argument)
{
	if (!node)
		return BOOL_FALSE;
	if (klysc_ext(node->exts, module, name, argument))
		return BOOL_TRUE;

	return BOOL_FALSE;
}


// Get extension by name from type
bool_t klysc_type_ext(const struct lysc_type *type,
	const char *module, const char *name, const char **argument)
{
	if (!type)
		return BOOL_FALSE;
	if (klysc_ext(type->exts, module, name, argument))
		return BOOL_TRUE;

	return BOOL_FALSE;
}


// Get extension by name from node or type
bool_t klysc_node_or_type_ext(const struct lysc_node *node,
	const char *module, const char *name, const char **argument)
{
	struct lysc_type *type = NULL;

	if (!node)
		return BOOL_FALSE;
	if (klysc_node_ext(node, module, name, argument))
		return BOOL_TRUE;
	switch (node->nodetype) {
	case LYS_LEAF:
		type = ((struct lysc_node_leaf *)node)->type;
		break;
	case LYS_LEAFLIST:
		type = ((struct lysc_node_leaflist *)node)->type;
		break;
	default:
		return BOOL_FALSE;
	}
	if (klysc_type_ext(type, module, name, argument))
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

	klysc_node_or_type_ext(node, "klish", "completion", &xpath);

	return xpath;
}


const char *klysc_node_ext_default(const struct lysc_node *node)
{
	const char *dflt = NULL;

	klysc_node_ext(node, "klish", "default", &dflt);

	return dflt;
}


char *klyd_esc_value(const char *value)
{
	char *space = NULL;
	char *escaped = NULL;
	char *result = NULL;

	if (!value)
		return NULL;

	escaped = faux_str_c_esc(value);
	// String with space must have quotes
	space = strchr(escaped, ' ');
	if (space) {
		result = faux_str_sprintf("\"%s\"", escaped);
		faux_str_free(escaped);
	} else {
		result = escaped;
	}

	return result;
}


// Get value from data lyd node
char *klyd_node_value(const struct lyd_node *node)
{
	const struct lysc_node *schema = NULL;
	const struct lysc_type *type = NULL;
	const char *origin_value = NULL;

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

	return klyd_esc_value(origin_value);
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


static struct lysc_ident *klysc_find_ident(struct lysc_ident *ident, const char *name)
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


const char *klysc_identityref_prefix(struct lysc_type_identityref *type,
	const char *name)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	assert(type);

	LY_ARRAY_FOR(type->bases, u) {
		struct lysc_ident *identity = klysc_find_ident(type->bases[u], name);
		if (identity)
			return identity->module->name;
	}

	return NULL;
}


// Get module name by internal prefix. Sysrepo requests use module names but not
// prefixes.
static const char *module_by_prefix(const struct lysp_module *parsed, const char *prefix)
{
	LY_ARRAY_COUNT_TYPE u = 0;

	if (!parsed)
		return NULL;
	if (!prefix)
		return NULL;

	// Try prefix of module itself
	if (faux_str_cmp(prefix, parsed->mod->prefix) == 0)
		return parsed->mod->name;

	// Try imported modules
	LY_ARRAY_FOR(parsed->imports, u) {
		const struct lysp_import *import = &parsed->imports[u];
		if (faux_str_cmp(prefix, import->prefix) == 0)
			return import->name;
	}

	return NULL;
}


static char *remap_xpath_prefixes(const char *orig_xpath, const struct lysp_module *parsed)
{
	char *remaped = NULL;
	const char *pos = orig_xpath;
	const char *start = orig_xpath;
	char *cached_prefix = NULL;
	char *cached_module = NULL;

	if (!orig_xpath)
		return NULL;

	while (*pos != '\0') {
		if (*pos == '/') {
			faux_str_catn(&remaped, start, pos - start + 1);
			start = pos + 1;
		} else if (*pos == ':') {
			if (pos != start) {
				char *prefix = faux_str_dupn(start, pos - start);
				if (cached_prefix && (faux_str_cmp(prefix, cached_prefix) == 0)) {
					faux_str_cat(&remaped, cached_module);
					faux_str_free(prefix);
				} else {
					const char *module = module_by_prefix(parsed, prefix);
					if (module) {
						faux_str_cat(&remaped, module);
						faux_str_free(cached_prefix);
						faux_str_free(cached_module);
						cached_prefix = prefix;
						cached_module = faux_str_dup(module);
					} else {
						faux_str_cat(&remaped, prefix);
						faux_str_free(prefix);
					}
				}
			}
			faux_str_cat(&remaped, ":");
			start = pos + 1;
		}
		pos++;
	}
	if (start != pos)
		faux_str_catn(&remaped, start, pos - start);

	faux_str_free(cached_prefix);
	faux_str_free(cached_module);

	return remaped;
}


static const char *cut_front_ups(const char *orig_xpath, size_t *up_num)
{
	const char *xpath = orig_xpath;
	const char *needle = "../";
	size_t needle_len = strlen(needle);
	size_t num = 0;

	if (!xpath)
		return NULL;

	while (faux_str_cmpn(xpath, needle, needle_len) == 0) {
		num++;
		xpath += needle_len;
	}

	if (up_num)
		*up_num = num;

	return xpath;
}


static char *cut_trailing_components(const char *orig_xpath, size_t up_num)
{
	const char *xpath = NULL;
	char *res = NULL;
	size_t num = 0;

	if (!orig_xpath)
		return NULL;

	xpath = orig_xpath + strlen(orig_xpath);
	while (xpath >= orig_xpath) {
		if (*xpath == '/')
			num++;
		if (num == up_num) {
			res = faux_str_dupn(orig_xpath, xpath - orig_xpath + 1);
			break;
		}
		xpath--;
	}

	return res;
}


char *klysc_leafref_xpath(const struct lysc_node *node,
	const struct lysc_type *type, const char *node_path)
{
	char *compl_xpath = NULL;
	const struct lysc_type_leafref *leafref = NULL;
	const char *orig_xpath = NULL;
	char *remaped_xpath = NULL;
	const char *tmp = NULL;
	size_t up_num = 0;

	if (!type)
		return NULL;
	if (!node)
		return NULL;
	if (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST)))
		return NULL;
	if (type->basetype != LY_TYPE_LEAFREF)
		return NULL;

	leafref = (const struct lysc_type_leafref *)type;

	orig_xpath = lyxp_get_expr(leafref->path);
	if (!orig_xpath)
		return NULL;

	remaped_xpath = remap_xpath_prefixes(orig_xpath, node->module->parsed);

	if (remaped_xpath[0] == '/') // Absolute path
		return remaped_xpath;

	// Relative path
	if (!node_path) {
		faux_str_free(remaped_xpath);
		return NULL;
	}

	tmp = cut_front_ups(remaped_xpath, &up_num);
	compl_xpath = cut_trailing_components(node_path, up_num);
	if (!compl_xpath) {
		faux_str_free(remaped_xpath);
		return NULL;
	}

	faux_str_cat(&compl_xpath, tmp);
	faux_str_free(remaped_xpath);

	return compl_xpath;
}


size_t klyd_visible_child_num(const struct lyd_node *node)
{
	const struct lyd_node *nodes_list = NULL;
	const struct lyd_node *iter = NULL;
	size_t num = 0;

	if (!node)
		return 0;
	nodes_list = lyd_child(node);
	if(!nodes_list)
		return 0;

	LY_LIST_FOR(nodes_list, iter) {
		if (iter->flags & LYD_DEFAULT)
			continue;
		if (!(iter->schema->nodetype & SRP_NODETYPE_CONF))
			continue;
		if (!(iter->schema->flags & LYS_CONFIG_W)) // config is true
			continue;
		if (iter->schema->flags & LYS_KEY)
			continue;
		num++;
	}

	return num;
}


bool_t kly_str2ds(const char *str, size_t len, sr_datastore_t *ds)
{
	if (!str)
		return BOOL_FALSE;
	if (len == 0)
		return BOOL_FALSE;
	if (!ds)
		return BOOL_FALSE;

	if (faux_str_cmpn(str, "candidate", len) == 0)
		*ds = SR_DS_CANDIDATE;
	else if (faux_str_cmpn(str, "running", len) == 0)
		*ds = SR_DS_RUNNING;
	else if (faux_str_cmpn(str, "operational", len) == 0)
		*ds = SR_DS_OPERATIONAL;
	else if (faux_str_cmpn(str, "startup", len) == 0)
		*ds = SR_DS_STARTUP;
#ifdef SR_DS_FACTORY_DEFAULT
	else if (faux_str_cmpn(str, "factory-default", len) == 0)
		*ds = SR_DS_FACTORY_DEFAULT;
#endif
	else // No DS prefix found
		return BOOL_FALSE;

	return BOOL_TRUE;
}


bool_t kly_parse_ext_xpath(const char *xpath, const char **raw_xpath,
	sr_datastore_t *ds)
{
	char *space = NULL;

	if (!xpath)
		return BOOL_FALSE;
	if (!raw_xpath)
		return BOOL_FALSE;
	if (!ds)
		return BOOL_FALSE;

	*ds = SRP_REPO_EDIT; // Default
	*raw_xpath = xpath;
	space = strchr(xpath, ' ');
	if (space) {
		size_t len = space - xpath;
		if (kly_str2ds(xpath, len, ds))
			*raw_xpath = space + 1;
	}

	return BOOL_TRUE;
}
