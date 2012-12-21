/*
 * options.h -- nsd.conf options definitions and prototypes
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdarg.h>
#include "region-allocator.h"
#include "rbtree.h"
struct query;
struct dname;
struct tsig_key;

typedef struct nsd_options nsd_options_t;
typedef struct pattern_options pattern_options_t;
typedef struct zone_options zone_options_t;
typedef struct ipaddress_option ip_address_option_t;
typedef struct acl_options acl_options_t;
typedef struct key_options key_options_t;
typedef struct config_parser_state config_parser_state_t;
/*
 * Options global for nsd.
 */
struct nsd_options {
	/* options for zones, by apex, contains zone_options_t */
	rbtree_t* zone_options;
	/* patterns, by name, contains pattern_options_t */
	rbtree_t* patterns;

	/* free space in zonelist file, contains zonelist_bucket */
	rbtree_t* zonefree;
	/* zonelist file if open */
	FILE* zonelist;
	/* last offset in file (or 0 if none) */
	off_t zonelist_off;
	/* actual zonelist file name in use */
	char* zlfile;

	/* list of keys defined */
	key_options_t* keys;
	size_t numkeys;

	/* list of ip adresses to bind to (or NULL for all) */
	ip_address_option_t* ip_addresses;

	int debug_mode;
	int verbosity;
	int hide_version;
	int ip4_only;
	int ip6_only;
	const char* database;
	const char* identity;
	const char* logfile;
	int server_count;
	int tcp_count;
	int tcp_query_count;
	int tcp_timeout;
	size_t ipv4_edns_size;
	size_t ipv6_edns_size;
	const char* pidfile;
	const char* port;
	int statistics;
	const char* chroot;
	const char* username;
	const char* zonesdir;
	const char* difffile;
	const char* xfrdfile;
	const char* zonelistfile;
	const char* nsid;
	int xfrd_reload_timeout;

	region_type* region;
};

struct ipaddress_option {
	ip_address_option_t* next;
	char* address;
};

/*
 * Pattern of zone options, used to contain options for zone(s).
 */
struct pattern_options {
	rbnode_t node;
	const char* pname; /* name of the pattern, key of rbtree */
	const char* zonefile;
	acl_options_t* allow_notify;
	acl_options_t* request_xfr;
	acl_options_t* notify;
	acl_options_t* provide_xfr;
	acl_options_t* outgoing_interface;
	uint8_t allow_axfr_fallback;
	uint8_t allow_axfr_fallback_is_default;
	uint8_t notify_retry;
	uint8_t notify_retry_is_default;
	uint8_t implicit; /* pattern is implicit, part_of_config zone used */
};

/*
 * Options for a zone
 */
struct zone_options {
	/* key is dname of apex */
	rbnode_t node;

	/* is apex of the zone */
	const char* name;
	/* if not part of config, the offset and linesize of zonelist entry */
	off_t off;
	int linesize;
	/* pattern for the zone options, if zone is part_of_config, this is
	 * a anonymous pattern created in-place */
	pattern_options_t* pattern;
	/* zone is fixed into the main config, not in zonelist, cannot delete */
	uint8_t part_of_config;
};

union acl_addr_storage {
#ifdef INET6
	struct in_addr addr;
	struct in6_addr addr6;
#else
	struct in_addr addr;
#endif
};

/*
 * Access control list element
 */
struct acl_options {
	acl_options_t* next;

	/* options */
	uint8_t use_axfr_only;
	uint8_t allow_udp;
	time_t ixfr_disabled;

	/* ip address range */
	const char* ip_address_spec;
	uint8_t is_ipv6;
	unsigned int port;	/* is 0(no port) or suffix @port value */
	union acl_addr_storage addr;
	union acl_addr_storage range_mask;
	enum {
		acl_range_single = 0,	/* single adress */
		acl_range_mask = 1,	/* 10.20.30.40&255.255.255.0 */
		acl_range_subnet = 2,	/* 10.20.30.40/28 */
		acl_range_minmax = 3	/* 10.20.30.40-10.20.30.60 (mask=max) */
	} rangetype;

	/* key */
	uint8_t nokey;
	uint8_t blocked;
	const char* key_name;
	key_options_t* key_options;
};

/*
 * Key definition
 */
struct key_options {
	key_options_t* next;
	const char* name;
	const char* algorithm;
	const char* secret;
	struct tsig_key* tsig_key;
};

/** zone list free space */
struct zonelist_free {
	struct zonelist_free* next;
	off_t off;
};
/** zonelist free bucket for a particular line length */
struct zonelist_bucket {
	rbnode_t node; /* key is ptr to linesize */
	int linesize;
	struct zonelist_free* list;
};

/*
 * Used during options parsing
 */
struct config_parser_state {
	const char* filename;
	int line;
	int errors;
	nsd_options_t* opt;
	pattern_options_t* current_pattern;
	zone_options_t* current_zone;
	key_options_t* current_key;
	ip_address_option_t* current_ip_address_option;
	acl_options_t* current_allow_notify;
	acl_options_t* current_request_xfr;
	acl_options_t* current_notify;
	acl_options_t* current_provide_xfr;
	acl_options_t* current_outgoing_interface;
};

extern config_parser_state_t* cfg_parser;

/* region will be put in nsd_options struct. Returns empty options struct. */
nsd_options_t* nsd_options_create(region_type* region);
/* the number of zones that are configured */
static inline size_t nsd_options_num_zones(nsd_options_t* opt)
{ return opt->zone_options->count; }
/* insert a zone into the main options tree, returns 0 on error */
int nsd_options_insert_zone(nsd_options_t* opt, zone_options_t* zone);
/* insert a pattern into the main options tree, returns 0 on error */
int nsd_options_insert_pattern(nsd_options_t* opt, pattern_options_t* pat);

/* parses options file. Returns false on failure */
int parse_options_file(nsd_options_t* opt, const char* file);
zone_options_t* zone_options_create(region_type* region);
pattern_options_t* pattern_options_create(region_type* region);
/* find a zone by apex domain name, or NULL if not found. */
zone_options_t* zone_options_find(nsd_options_t* opt, const struct dname* apex);
key_options_t* key_options_create(region_type* region);
key_options_t* key_options_find(nsd_options_t* opt, const char* name);
/* read in zone list file. Returns false on failure */
int parse_zone_list_file(nsd_options_t* opt, const char* zlfile);
zone_options_t* zone_list_add(nsd_options_t* opt, const char* zname,
	const char* pname);
void zone_list_del(nsd_options_t* opt, zone_options_t* zone);
void zone_list_compact(nsd_options_t* opt);
void zone_list_close(nsd_options_t* opt);

#if defined(HAVE_SSL)
/* tsig must be inited, adds all keys in options to tsig. */
void key_options_tsig_add(nsd_options_t* opt);
#endif

/* check acl list, acl number that matches if passed(0..),
 * or failure (-1) if dropped */
/* the reason why (the acl) is returned too (or NULL) */
int acl_check_incoming(acl_options_t* acl, struct query* q,
	acl_options_t** reason);
int acl_addr_matches(acl_options_t* acl, struct query* q);
int acl_key_matches(acl_options_t* acl, struct query* q);
int acl_addr_match_mask(uint32_t* a, uint32_t* b, uint32_t* mask, size_t sz);
int acl_addr_match_range(uint32_t* minval, uint32_t* x, uint32_t* maxval, size_t sz);

/* returns true if acls are both from the same host */
int acl_same_host(acl_options_t* a, acl_options_t* b);
/* find acl by number in the list */
acl_options_t* acl_find_num(acl_options_t* acl, int num);

/* see if a zone is a slave or a master zone */
int zone_is_slave(zone_options_t* opt);
/* create zonefile name, returns static pointer (perhaps to options data) */
const char* config_make_zonefile(zone_options_t* zone);

/* parsing helpers */
void c_error(const char* msg);
void c_error_msg(const char* fmt, ...) ATTR_FORMAT(printf, 1, 2);
acl_options_t* parse_acl_info(region_type* region, char* ip, const char* key);
/* true if ipv6 address, false if ipv4 */
int parse_acl_is_ipv6(const char* p);
/* returns range type. mask is the 2nd part of the range */
int parse_acl_range_type(char* ip, char** mask);
/* parses subnet mask, fills 0 mask as well */
void parse_acl_range_subnet(char* p, void* addr, int maxbits);
/* clean up options */
void nsd_options_destroy(nsd_options_t* opt);
/* replace occurrences of one with two in buf, pass length of buffer */
void replace_str(char* buf, size_t len, const char* one, const char* two);
/* apply pattern to the existing pattern in the parser */
void config_apply_pattern(const char* name);

#endif /* OPTIONS_H */