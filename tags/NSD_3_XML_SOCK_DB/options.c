/*
 * options.c -- maintain NSD configuration information.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include "options.h"

#include <assert.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "heap.h"
#include "nsd.h"
#include "util.h"

struct options_node
{
	heapnode_t heap_node;
	xmlNodePtr xml_node;
};
typedef struct options_node options_node_type;

/*
 * Validates OPTIONS_DOC against the RelaxNG SCHEMA_DOC.  Returns
 * non-zero on success, zero on failure.
 */
static int validate_config(xmlDocPtr schema_doc, xmlDocPtr options_doc);

static xmlNodePtr first_element(xmlNodePtr parent, const char *name);
static xmlNodePtr next_element(xmlNodePtr node, const char *name);

static int is_element(xmlNodePtr node, const char *name);
static size_t child_element_count(xmlNodePtr parent, const char *name);

static xmlNodePtr lookup_node(xmlXPathContextPtr context, const char *xpath);
static const char *lookup_text(region_type *region,
			       xmlXPathContextPtr context,
			       const char *expr);
static int lookup_integer(xmlXPathContextPtr context,
			  const char *expr,
			  int default_value);

static nsd_options_address_type *parse_address(region_type *region,
					       heap_t *nodes_by_id,
					       xmlNodePtr address_node);
static nsd_options_address_list_type *parse_address_list(region_type *region,
							 heap_t *nodes_by_id,
							 xmlNodePtr   parent);

static nsd_options_key_type *parse_key(region_type *region,
				       heap_t *nodes_by_id,
				       xmlNodePtr key_node);
static int parse_keys(nsd_options_type *options,
		      heap_t *nodes_by_id,
		      xmlXPathContextPtr context);


static nsd_options_acl_type *parse_acl(region_type *region,
				       heap_t *nodes_by_id,
				       xmlNodePtr acl_node);

static nsd_options_zone_type *parse_zone(region_type *region,
					 heap_t *nodes_by_id,
					 xmlNodePtr zone_node);
static int parse_zones(nsd_options_type *options,
		       heap_t *nodes_by_id,
		       xmlNodePtr parent);
static nsd_options_server_type *parse_server(region_type *region,
					     heap_t *nodes_by_id,
					     xmlNodePtr server_node);

static int compare_ids(const void *left, const void *right);
static int insert_elements_with_id(heap_t *heap, xmlNodePtr xml_node);
static xmlNodePtr follow_ref(heap_t *heap, xmlNodePtr node);

/*
 * Load the NSD configuration from FILENAME.
 */
nsd_options_type *
nsd_load_config(region_type *region, const char *filename)
{
	xmlDocPtr schema_doc = NULL;
	xmlDocPtr options_doc = NULL;
	xmlXPathContextPtr xpath_context = NULL;
	nsd_options_type *options = NULL;
	nsd_options_type *result = NULL;
	region_type *node_region = region_create(xalloc, free);
	heap_t *nodes_by_id = heap_create(node_region, compare_ids);

	assert(filename);

	xmlLineNumbersDefault(1);

	schema_doc = xmlParseFile(DATADIR "/nsd.rng");
	if (!schema_doc) {
		log_msg(LOG_WARNING, "cannot parse XML schema '%s', "
			"configuration file will not be validated",
			DATADIR "/nsd.rng");
	}

	options_doc = xmlParseFile(filename);
	if (!options_doc) {
		log_msg(LOG_ERR, "cannot parse NSD configuration '%s'",
			filename);
		goto exit;
	}

	if (schema_doc && options_doc) {
		if (!validate_config(schema_doc, options_doc)) {
			goto exit;
		} else {
			log_msg(LOG_INFO,
				"nsd configuration successfully validated");
		}
	}

	xpath_context = xmlXPathNewContext(options_doc);
	if (!xpath_context) {
		log_msg(LOG_ERR, "cannot create XPath context");
		goto exit;
	}

	if (!insert_elements_with_id(nodes_by_id,
				     xmlDocGetRootElement(options_doc)))
	{
		goto exit;
	}

	options = region_alloc(region, sizeof(nsd_options_type));
	options->region = region;
	options->user_id = lookup_text(region, xpath_context,
				       "/nsd/options/user-id/text()");
	options->database = lookup_text(region, xpath_context,
				       "/nsd/options/database/text()");
	options->version = lookup_text(region, xpath_context,
				       "/nsd/options/version/text()");
	options->identity = lookup_text(region, xpath_context,
					"/nsd/options/identity/text()");
	options->directory = lookup_text(region, xpath_context,
					 "/nsd/options/directory/text()");
	options->chroot_directory = lookup_text(
		region, xpath_context, "/nsd/options/chroot-directory/text()");
	options->log_file = lookup_text(region, xpath_context,
					"/nsd/options/log-file/text()");
	options->pid_file = lookup_text(region, xpath_context,
					"/nsd/options/pid-file/text()");
	options->statistics_period = lookup_integer(
		xpath_context, "/nsd/options/statistics-period/text()", 0);
	options->server_count = lookup_integer(
		xpath_context, "/nsd/options/server-count/text()", 1);
	options->maximum_tcp_connection_count = lookup_integer(
		xpath_context,
		"/nsd/options/maximum-tcp-connection-count/text()",
		10);
	options->listen_on = NULL;
	options->controls = NULL;
	options->key_count = 0;
	options->keys = NULL;
	options->zone_count = 0;
	options->zones = NULL;

	options->listen_on = parse_address_list(
		region,
		nodes_by_id,
		lookup_node(xpath_context, "/nsd/options/listen-on"));
	if (!options->listen_on) {
		goto exit;
	}
	options->controls = parse_address_list(
		region,
		nodes_by_id,
		lookup_node(xpath_context, "/nsd/options/controls"));
	if (!options->controls) {
		goto exit;
	}
	if (!parse_keys(options, nodes_by_id, xpath_context)) {
		goto exit;
	}
	if (!parse_zones(options, nodes_by_id, lookup_node(xpath_context, "/nsd"))) {
		goto exit;
	}

	result = options;
exit:
	xmlXPathFreeContext(xpath_context);
	xmlFreeDoc(schema_doc);
	xmlFreeDoc(options_doc);
	region_destroy(node_region);

	return result;
}


nsd_options_address_type *
options_address_make(region_type *region,
		     int family,
		     const char *port,
		     const char *address)
{
	nsd_options_address_type *result
		= region_alloc(region, sizeof(nsd_options_address_type));
	result->family = family;
	result->port = region_strdup(region, port);
	result->address = region_strdup(region, address);
	return result;
}


nsd_options_zone_type *
nsd_options_find_zone(nsd_options_type *options, const dname_type *name)
{
	size_t i;

	for (i = 0; i < options->zone_count; ++i) {
		if (dname_compare(name, options->zones[i]->name) == 0) {
			return options->zones[i];
		}
	}

	return NULL;
}



static int
validate_config(xmlDocPtr schema_doc, xmlDocPtr options_doc)
{
	xmlRelaxNGParserCtxtPtr schema_parser_ctxt = NULL;
	xmlRelaxNGPtr schema = NULL;
	xmlRelaxNGValidCtxtPtr schema_validator_ctxt = NULL;
	int valid;
	int result = 0;

	schema_parser_ctxt = xmlRelaxNGNewDocParserCtxt(schema_doc);
	if (!schema_parser_ctxt) {
		log_msg(LOG_ERR, "cannot create RelaxNG validation schema");
		goto exit;
	}

	schema = xmlRelaxNGParse(schema_parser_ctxt);
	if (!schema) {
		log_msg(LOG_ERR, "cannot parse RelaxNG schema");
		goto exit;
	}

	schema_validator_ctxt = xmlRelaxNGNewValidCtxt(schema);
	if (!schema_validator_ctxt) {
		log_msg(LOG_ERR, "cannot create RelaxNG validator");
		goto exit;
	}

	valid = xmlRelaxNGValidateDoc(schema_validator_ctxt, options_doc);
	if (valid == -1) {
		log_msg(LOG_ERR, "error while validating");
	} else if (valid == 0) {
		result = 1;
	} else {
		result = 0;
	}

exit:
	xmlRelaxNGFreeValidCtxt(schema_validator_ctxt);
	xmlRelaxNGFree(schema);
	xmlRelaxNGFreeParserCtxt(schema_parser_ctxt);

	return result;
}


static xmlNodePtr
first_element(xmlNodePtr parent, const char *name)
{
	xmlNodePtr current;

	assert(parent);

	for (current = parent->children; current; current = current->next) {
		if (is_element(current, name)) {
			return current;
		}
	}

	return NULL;
}

static xmlNodePtr
next_element(xmlNodePtr node, const char *name)
{
	xmlNodePtr current;

	assert(node);

	for (current = node->next; current; current = current->next) {
		if (is_element(current, name)) {
			return current;
		}
	}

	return NULL;
}

static int
is_element(xmlNodePtr node, const char *name)
{
	return (node
		&& node->type == XML_ELEMENT_NODE
		&& strcmp((const char *) node->name, name) == 0);
}

static size_t
child_element_count(xmlNodePtr parent, const char *name)
{
	size_t result = 0;
	xmlNodePtr current;

	if (!parent) {
		return 0;
	}

	for (current = parent->children; current; current = current->next) {
		if (is_element(current, name)) {
			++result;
		}
	}

	return result;
}

static xmlNodePtr
lookup_node(xmlXPathContextPtr context, const char *xpath)
{
	xmlXPathObjectPtr object = NULL;
	xmlNodePtr result = NULL;

	assert(context);
	assert(xpath);

	object = xmlXPathEvalExpression((const xmlChar *) xpath, context);
	if (!object) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			(const char *) xpath);
		goto exit;
	} else if (xmlXPathNodeSetIsEmpty(object->nodesetval)) {
		result = NULL;
	} else if (xmlXPathNodeSetGetLength(object->nodesetval) == 1) {
		result = xmlXPathNodeSetItem(object->nodesetval, 0);
	} else {
		log_msg(LOG_ERR,
			"xpath expression '%s' returned multiple results",
			(const char *) xpath);
	}

exit:
	xmlXPathFreeObject(object);
	return result;
}

static const char *
lookup_text(region_type *region,
	    xmlXPathContextPtr context,
	    const char *expr)
{
	xmlXPathObjectPtr object = NULL;
	const char *result = NULL;

	assert(context);
	assert(expr);

	object = xmlXPathEvalExpression((const xmlChar *) expr, context);
	if (!object) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			(const char *) expr);
		goto exit;
	}

	if (!object->nodesetval) {
		/* Option not specified, return NULL.  */
	} else if (object->nodesetval->nodeNr == 0) {
		/* Empty option, return empty string.  */
		result = "";
	} else if (object->nodesetval->nodeNr == 1) {
		xmlNodePtr node = object->nodesetval->nodeTab[0];
		if (node->type != XML_TEXT_NODE) {
			log_msg(LOG_ERR,
				"xpath expression '%s' did not evaluate to a "
				"text node",
				(const char *) expr);
		} else {
			xmlChar *content = xmlNodeGetContent(node);
			if (content) {
				result = region_strdup(region,
						       (const char *) content);
				xmlFree(content);
			}
		}
	} else {
		log_msg(LOG_ERR,
			"xpath expression '%s' returned multiple results",
			(const char *) expr);
	}

exit:
	xmlXPathFreeObject(object);
	return result;
}

static int
lookup_integer(xmlXPathContextPtr context,
	       const char *expr,
	       int default_value)
{
	region_type *temp = region_create(xalloc, free);
	const char *text = lookup_text(temp, context, expr);
	int result = default_value;

	if (text) {
		result = atoi(text);
	}

	region_destroy(temp);
	return result;
}

static const char *
get_attribute_text(xmlNodePtr node, const char *attribute)
{
	xmlAttrPtr attr = xmlHasProp(node, (const xmlChar *) attribute);
	if (attr && attr->children && attr->children->type == XML_TEXT_NODE) {
		return (const char *) attr->children->content;
	} else {
		return NULL;
	}
}

static const char *
get_element_text(xmlNodePtr node, const char *element)
{
	xmlNodePtr current;
	for (current = node->children; current; current = current->next) {
		if (current->type == XML_ELEMENT_NODE
		    && strcmp((const char *) current->name, element) == 0
		    && current->children
		    && current->children->type == XML_TEXT_NODE)
		{
			return (const char *) current->children->content;
		}
	}
	return NULL;
}


static nsd_options_address_type *
parse_address(region_type *region,
	      heap_t *nodes_by_id,
	      xmlNodePtr address_node)
{
	nsd_options_address_type *result = NULL;
	const char *port;
	const char *family_text;
	int family;

	address_node = follow_ref(nodes_by_id, address_node);

	port = get_attribute_text(address_node, "port");
	family_text = get_attribute_text(address_node, "family");

	if (!address_node->children
	    || address_node->children->type != XML_TEXT_NODE)
	{
		log_msg(LOG_ERR, "address not specified at line %d",
			address_node->line);
		goto exit;
	}

	if (family_text) {
		if (strcasecmp(family_text, "ipv4") == 0) {
			family = AF_INET;
		} else if (strcasecmp(family_text, "ipv6") == 0) {
			family = AF_INET6;
		} else {
			log_msg(LOG_ERR, "unrecognized protocol family '%s'",
				family_text);
			goto exit;
		}
	} else {
		family = DEFAULT_AI_FAMILY;
	}

	result = region_alloc(region, sizeof(nsd_options_address_type));
	result->family = family;
	result->port = region_strdup(region, port);
	result->address = region_strdup(
		region,	(const char *) address_node->children->content);

exit:
	return result;
}

static nsd_options_address_list_type *
parse_address_list(region_type *region,
		   heap_t *nodes_by_id,
		   xmlNodePtr parent)
{
	nsd_options_address_list_type *result;
	xmlNodePtr current;
	size_t i;

	if (!parent) {
		return NULL;
	}

	result = region_alloc(region, sizeof(nsd_options_address_list_type));
	result->count = child_element_count(parent, "address");
	result->addresses = region_alloc(
		region, result->count * sizeof(nsd_options_address_type *));

	for (i = 0, current = first_element(parent, "address");
	     current;
	     ++i, current = next_element(current, "address"))
	{
		assert(i < result->count);
		result->addresses[i] = parse_address(
			region, nodes_by_id, current);
		if (!result->addresses[i]) {
			return NULL;
		}
	}

	return result;
}


static nsd_options_key_type *
parse_key(region_type *region,
	  heap_t *nodes_by_id,
	  xmlNodePtr key_node)
{
	nsd_options_key_type *result = NULL;
	const char *name;
	const char *algorithm;
	const char *secret;

	key_node = follow_ref(nodes_by_id, key_node);

	name = get_element_text(key_node, "name");
	algorithm = get_element_text(key_node, "algorithm");
	secret = get_element_text(key_node, "secret");

	if (!name || !algorithm || !secret) {
		log_msg(LOG_ERR,
			"key at line %d does not define one of name, algorithm, or secret",
			key_node->line);
		return NULL;
	}

	result = region_alloc(region, sizeof(nsd_options_key_type));

	result->name = dname_parse(region, name);
	if (!result->name) {
		log_msg(LOG_ERR,
			"key name at line %d is not a valid domain name",
			key_node->line);
		return NULL;
	}

	result->algorithm = region_strdup(region, algorithm);
	result->secret = region_strdup(region, secret);

	return result;
}

static int
parse_keys(nsd_options_type *options,
	   heap_t *nodes_by_id,
	   xmlXPathContextPtr context)
{
	int result = 0;
	xmlXPathObjectPtr keys = NULL;

	keys = xmlXPathEvalExpression(
		(const xmlChar *) "/nsd/key",
		context);
	if (!keys) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			"/nsd/key");
		goto exit;
	} else if (keys->nodesetval) {
		int i;

		assert(keys->type == XPATH_NODESET);

		result = 1;
		options->key_count
			= keys->nodesetval->nodeNr;
		options->keys = region_alloc(
			options->region,
			(options->key_count
			 * sizeof(nsd_options_key_type *)));
		for (i = 0; i < keys->nodesetval->nodeNr; ++i) {
			options->keys[i] = parse_key(
				options->region,
				nodes_by_id,
				keys->nodesetval->nodeTab[i]);
			if (!options->keys[i]) {
				result = 0;
			}
		}
	}

exit:
	xmlXPathFreeObject(keys);
	return result;
}


static nsd_options_acl_entry_type *
parse_acl_entry(region_type *region,
		heap_t *nodes_by_id,
		xmlNodePtr entry_node)
{
	nsd_options_acl_entry_type *result;

	result = region_alloc(region, sizeof(nsd_options_acl_entry_type));
	if (is_element(entry_node, "allow")) {
		result->allow = 1;
	} else if (is_element(entry_node, "deny")) {
		result->allow = 0;
	} else {
		log_msg(LOG_ERR, "%s element at line %d is not allow or deny",
			entry_node->name,
			entry_node->line);
		return NULL;
	}

	result->address = NULL;
	result->key = NULL;
	if (first_element(entry_node, "address")) {
		result->address = parse_address(
			region,
			nodes_by_id,
			first_element(entry_node, "address"));
		if (!result->address) {
			return NULL;
		}
	} else if (first_element(entry_node, "key")) {
		result->key = parse_key(
			region,
			nodes_by_id,
			first_element(entry_node, "key"));
		if (!result->key) {
			return NULL;
		}
	}

	if (result->address && result->key) {
		log_msg(LOG_ERR,
			"%s element at line %d specifies both key and address",
			entry_node->name,
			entry_node->line);
		return NULL;
	}

	return result;
}


static nsd_options_acl_type *
parse_acl(region_type *region,
	  heap_t *nodes_by_id,
	  xmlNodePtr acl_node)
{
	nsd_options_acl_type *result = NULL;
	const char *action_text;
	nsd_options_acl_action_type action;
	size_t i;
	xmlNodePtr current;

	acl_node = follow_ref(nodes_by_id, acl_node);

	action_text = get_attribute_text(acl_node, "action");
	if (!action_text) {
		log_msg(LOG_ERR,
			"acl element at line %d does not define action",
			acl_node->line);
		return NULL;
	}

	if (strcasecmp(action_text, "control") == 0) {
		action = NSD_OPTIONS_ACL_ACTION_CONTROL;
	} else if (strcasecmp(action_text, "notify") == 0) {
		action = NSD_OPTIONS_ACL_ACTION_NOTIFY;
	} else if (strcasecmp(action_text, "query") == 0) {
		action = NSD_OPTIONS_ACL_ACTION_QUERY;
	} else if (strcasecmp(action_text, "transfer") == 0) {
		action = NSD_OPTIONS_ACL_ACTION_TRANSFER;
	} else {
		log_msg(LOG_ERR,
			"unrecognized ACL action '%s'",
			action_text);
		return NULL;
	}

	result = region_alloc(region, sizeof(nsd_options_acl_type));
	result->action = action;
	result->acl_entry_count	= (child_element_count(acl_node, "allow")
				   + child_element_count(acl_node, "deny"));
	result->acl_entries = region_alloc(
		region,
		result->acl_entry_count * sizeof(nsd_options_acl_entry_type *));

	i = 0;
	for (current = acl_node->children;
	     current;
	     current = current->next)
	{
		if (!is_element(current, "allow")
		    && !is_element(current, "deny"))
		{
			continue;
		}

		assert(i < result->acl_entry_count);

		result->acl_entries[i] = parse_acl_entry(
			region, nodes_by_id, current);
		if (!result->acl_entries[i]) {
			return NULL;
		}

		++i;
	}

	return result;
}


static nsd_options_zone_type *
parse_zone(region_type *region,
	   heap_t *nodes_by_id,
	   xmlNodePtr zone_node)
{
	nsd_options_zone_type *result = NULL;
	const char *name = get_element_text(zone_node, "name");
	const char *file = get_element_text(zone_node, "file");
	xmlNodePtr masters_node;
	xmlNodePtr notify_node;
	xmlNodePtr current;
	size_t i;
	const dname_type *dname;

	if (!name || !file) {
		log_msg(LOG_ERR,
			"zone element at line %d does not define name or file",
			zone_node->line);
		return NULL;
	}

	dname = dname_parse(region, name);
	if (!dname) {
		log_msg(LOG_ERR,
			"zone name '%s' is not a valid domain name",
			name);
	}

	masters_node = first_element(zone_node, "masters");
	notify_node = first_element(zone_node, "notify");

	result = region_alloc(region, sizeof(nsd_options_zone_type));
	result->name = dname;
	result->file = region_strdup(region, file);
	result->master_count = child_element_count(masters_node, "server");
	result->masters = region_alloc(
		region,
		result->master_count * sizeof(nsd_options_server_type *));
	result->notify_count = child_element_count(notify_node, "server");
	result->notify = region_alloc(
		region,
		result->notify_count * sizeof(nsd_options_server_type *));
	result->acl_count = child_element_count(zone_node, "acl");
	result->acls = region_alloc(
		region,
		result->acl_count * sizeof(nsd_options_acl_type *));

	if (masters_node) {
		for (i = 0, current = first_element(masters_node, "server");
		     current;
		     ++i, current = next_element(current, "server"))
		{
			assert(i < result->master_count);
			result->masters[i] = parse_server(
				region, nodes_by_id, current);
			if (!result->masters[i]) {
				return NULL;
			}
		}
	}

	if (notify_node) {
		for (i = 0, current = first_element(notify_node, "server");
		     current;
		     ++i, current = next_element(current, "server"))
		{
			assert(i < result->notify_count);
			result->notify[i] = parse_server(
				region, nodes_by_id, current);
			if (!result->notify[i]) {
				return NULL;
			}
		}
	}

	for (i = 0, current = first_element(zone_node, "acl");
	     current;
	     ++i, current = next_element(current, "acl"))
	{
		assert(i < result->acl_count);
		result->acls[i] = parse_acl(region, nodes_by_id, current);
		if (!result->acls[i]) {
			return NULL;
		}
	}

	return result;
}

static int
parse_zones(nsd_options_type *options,
	    heap_t *nodes_by_id,
	    xmlNodePtr parent)
{
	int result = 1;
	xmlNodePtr current;
	size_t i;

	options->zone_count = child_element_count(parent, "zone");
	options->zones = region_alloc(
		options->region,
		options->zone_count * sizeof(nsd_options_zone_type *));

	for (i = 0, current = first_element(parent, "zone");
	     current;
	     ++i, current = next_element(current, "zone"))
	{
		options->zones[i] = parse_zone(options->region, nodes_by_id, current);
		if (!options->zones[i]) {
			result = 0;
			break;
		}
	}

	return result;
}

static nsd_options_server_type *
parse_server(region_type *region,
	     heap_t *nodes_by_id,
	     xmlNodePtr server_node)
{
	nsd_options_server_type *result;

	assert(server_node);

	result = region_alloc(region, sizeof(nsd_options_server_type));
	result->key = NULL;
	result->addresses = parse_address_list(region, nodes_by_id, server_node);
	if (!result->addresses) {
		return NULL;
	}

	return result;
}

static int
compare_ids(const void *left, const void *right)
{
	return strcmp(left, right);
}

static int
insert_elements_with_id(heap_t *heap, xmlNodePtr xml_node)
{
	int result = 1;
	const char *id;

	assert(xml_node);
	assert(xml_node->type == XML_ELEMENT_NODE);

	id = get_attribute_text(xml_node, "id");
	if (id) {
		heapnode_t *heap_node = heap_search(heap, id);
		if (heap_node) {
			options_node_type *options_node
				= (options_node_type *) heap_node;
			log_msg(LOG_ERR,
				"id on line %d duplicates id on line %d",
				xml_node->line,
				options_node->xml_node->line);
			result = 0;
		} else if (get_attribute_text(xml_node, "ref")) {
			log_msg(LOG_ERR,
				"node '%s' on line %d has both an id and ref attribute",
				xml_node->name,
				xml_node->line);
			result = 0;
		} else {
			options_node_type *options_node
				= region_alloc(heap->region,
					       sizeof(options_node_type));
			options_node->heap_node.key = id;
			options_node->xml_node = xml_node;
			heap_insert(heap, (heapnode_t *) options_node);
		}
	}

	for (xml_node = xml_node->children;
	     xml_node;
	     xml_node = xml_node->next)
	{
		if (xml_node->type == XML_ELEMENT_NODE) {
			if (!insert_elements_with_id(heap, xml_node)) {
				result = 0;
			}
		}
	}

	return result;
}

static xmlNodePtr
follow_ref(heap_t *heap, xmlNodePtr node)
{
	const char *ref;
	heapnode_t *heapnode;

	assert(node);

	ref = get_attribute_text(node, "ref");
	if (!ref) {
		return node;
	}

	heapnode = heap_search(heap, ref);
	if (!heapnode) {
		log_msg(LOG_ERR,
			"node '%s' on line %d references non-existant node '%s'",
			node->name,
			node->line,
			ref);
		return NULL;
	}

	return ((options_node_type *) heapnode)->xml_node;
}

const char *
action_to_string(nsd_options_acl_action_type action)
{
	static const char *action_table[] = {
		"control",
		"notify",
		"query",
		"transfer"
	};

	assert(action <= NSD_OPTIONS_ACL_ACTION_TRANSFER);

	return action_table[action];
}