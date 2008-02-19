/*
 * nsd-plugin.h -- interface to NSD for a plugin.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _NSD_PLUGIN_H_
#define _NSD_PLUGIN_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef PLUGINS
#error "Plugin support not enabled."
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "query.h"

/*
 * The version of the plugin interface and the name of the plugin
 * initialization function.
 */
#define NSD_PLUGIN_INTERFACE_VERSION 1
#define NSD_PLUGIN_INIT nsd_plugin_init_1

/*
 * Every plugin is assigned a unique id when loaded.  If a single
 * plugin is loaded multiple times it will have multiple unique ids.
 */
typedef unsigned nsd_plugin_id_type;


/*
 * A plugin can control how further processing should be done after
 * returning from a callback.
 */
enum nsd_plugin_callback_result
{
	/*
	 * Continue processing, everything is ok.
	 */
	NSD_PLUGIN_CONTINUE,
	
	/*
	 * Send the current answer to the client without further
	 * processing.
	 */
	NSD_PLUGIN_ANSWER,
	
	/*
	 * Plugin failed.  Return an error to the client.  The error
	 * code must be in the result_code field of the
	 * nsd_plugin_callback_args_type structure.
	 */
	NSD_PLUGIN_ERROR,
	
	/*
	 * Abandon client request (no answer is send at all).
	 */
	NSD_PLUGIN_ABANDON
	
};
typedef enum nsd_plugin_callback_result nsd_plugin_callback_result_type;


/*
 * Arguments passed to a plugin callback.
 */
struct nsd_plugin_callback_args
{
	/* Always non-NULL.  */
	struct query        *query;
	
	/*
	 * NULL for the NSD_PLUGIN_QUERY_RECEIVED callback and for plugins
	 * that have not registered any data for the domain_name.
	 */
	void                *data;

	/*
	 * Set this if the callback returns NSD_PLUGIN_ERROR.
	 */
	nsd_rc_type          result_code;
};
typedef struct nsd_plugin_callback_args nsd_plugin_callback_args_type;


/*
 * Plugin interface to NSD.
 */
struct nsd_plugin_interface
{
	struct nsd *nsd;

	const dname_type *root_dname;
	
	/*
	 * Register plugin specific data for the specified
	 * domain_name.  The plugin remains responsible for correctly
	 * deallocating the registered data on a reload.
	 */
	int (*register_data)(
		const struct nsd_plugin_interface *nsd,
		nsd_plugin_id_type                 plugin_id,
		const dname_type *                 domain_name,
		void *                             data);

	void (*log_msg)(int priority, const char *format, ...) ATTR_FORMAT(printf, 2, 3);
	
	void *(*xalloc)(size_t size);
	void *(*xrealloc)(void *ptr, size_t size);
	void (*free)(void *ptr);

	region_type *(*region_create)(void *(*allocator)(size_t),
				      void (*deallocator)(void *));
	void (*region_destroy)(region_type *region);
	void *(*region_alloc)(region_type *region, size_t size);
	void (*region_free_all)(region_type *region);

	const dname_type *(*dname_parse)(region_type *region, const char *name);

	const char *(*dname_to_string)(const dname_type *dname,
				       const dname_type *origin);
};
typedef struct nsd_plugin_interface nsd_plugin_interface_type;


/*
 * The type of a plugin callback function.
 */
typedef nsd_plugin_callback_result_type nsd_plugin_callback_type(
	const nsd_plugin_interface_type *nsd,
	nsd_plugin_id_type               plugin_id,
	nsd_plugin_callback_args_type   *args);


/*
 * NSD interface to the plugin.
 */
struct nsd_plugin_descriptor
{
	/*
	 * The name of the plugin.
	 */
	const char *name;

	/*
	 * The version of the plugin.
	 */
	const char *version;

	/*
	 * Called right before NSD shuts down.
	 */
	void (*finalize)(
		const nsd_plugin_interface_type *interface,
		nsd_plugin_id_type id);

	/*
	 * Called right after the database has been reloaded.  If the
	 * plugin has registered any data that it does not re-register
	 * it needs to deallocate this data to avoid memory leaks.
	 */
	nsd_plugin_callback_result_type (*reload)(
		const nsd_plugin_interface_type *interface,
		nsd_plugin_id_type id);
	
	/*
	 * Called right after a query has been received but before
	 * being NSD does _any_ processing.
	 */
	nsd_plugin_callback_type *query_received;

	/*
	 * Called right after the answer has been constructed but
	 * before it has been send to the client.
	 */
	nsd_plugin_callback_type *query_processed;
};
typedef struct nsd_plugin_descriptor nsd_plugin_descriptor_type;


typedef const nsd_plugin_descriptor_type *nsd_plugin_init_type(
	const nsd_plugin_interface_type *interface,
	nsd_plugin_id_type plugin_id,
	const char *arg);


/*
 * The following function must be defined by the plugin.  It is called
 * by NSD when the plugin is loaded.  Return NULL if the plugin cannot
 * be initialized.
 */
extern nsd_plugin_init_type NSD_PLUGIN_INIT;

#endif /* _PLUGINS_H_ */