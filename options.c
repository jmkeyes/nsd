/*
 * options.c -- options functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "options.h"
#include "query.h"
#include "tsig.h"
#include "difffile.h"

#include "configyyrename.h"
#include "configparser.h"
nsd_options_t* nsd_options = 0;
config_parser_state_t* cfg_parser = 0;
extern FILE* c_in, *c_out;
int c_parse(void);
int c_lex(void);
int c_wrap(void);
void c_error(const char *message);

static int pat_cmp(const void* p1, const void* p2)
{
	return strcmp((const char*)p1, (const char*)p2);
}

nsd_options_t* nsd_options_create(region_type* region)
{
	nsd_options_t* opt;
	opt = (nsd_options_t*)region_alloc(region, sizeof(nsd_options_t));
	opt->region = region;
	opt->zone_options = rbtree_create(region,
		(int (*)(const void *, const void *)) dname_compare);
	opt->patterns = rbtree_create(region, pat_cmp);
	opt->keys = NULL;
	opt->numkeys = 0;
	opt->ip_addresses = NULL;
	opt->debug_mode = 0;
	opt->verbosity = 0;
	opt->hide_version = 0;
	opt->ip4_only = 0;
	opt->ip6_only = 0;
	opt->database = DBFILE;
	opt->identity = 0;
	opt->nsid = 0;
	opt->logfile = 0;
	opt->server_count = 1;
	opt->tcp_count = 10;
	opt->tcp_query_count = 0;
	opt->tcp_timeout = TCP_TIMEOUT;
	opt->ipv4_edns_size = EDNS_MAX_MESSAGE_LEN;
	opt->ipv6_edns_size = EDNS_MAX_MESSAGE_LEN;
	opt->pidfile = PIDFILE;
	opt->port = UDP_PORT;
/* deprecated?	opt->port = TCP_PORT; */
	opt->statistics = 0;
	opt->chroot = 0;
	opt->username = USER;
	opt->zonesdir = ZONESDIR;
	opt->difffile = DIFFFILE;
	opt->xfrdfile = XFRDFILE;
	opt->xfrd_reload_timeout = 1;
	nsd_options = opt;
	return opt;
}

int nsd_options_insert_zone(nsd_options_t* opt, zone_options_t* zone)
{
	/* create dname for lookup */
	const dname_type* dname = dname_parse(opt->region, zone->name);
	if(!dname)
		return 0;
	zone->node.key = dname;
	if(!rbtree_insert(opt->zone_options, (rbnode_t*)zone))
		return 0;
	return 1;
}

int nsd_options_insert_pattern(nsd_options_t* opt, pattern_options_t* pat)
{
	pat->node.key = pat->pname;
	if(!rbtree_insert(opt->patterns, (rbnode_t*)pat))
		return 0;
	return 1;
}

int parse_options_file(nsd_options_t* opt, const char* file)
{
	FILE *in = 0;
	pattern_options_t* pat;
	acl_options_t* acl;

	if(!cfg_parser)
		cfg_parser = (config_parser_state_t*)region_alloc(
			opt->region, sizeof(config_parser_state_t));
	cfg_parser->filename = file;
	cfg_parser->line = 1;
	cfg_parser->errors = 0;
	cfg_parser->opt = opt;
	cfg_parser->current_pattern = 0;
	cfg_parser->current_zone = 0;
	cfg_parser->current_key = opt->keys;
	while(cfg_parser->current_key && cfg_parser->current_key->next)
		cfg_parser->current_key = cfg_parser->current_key->next;
	cfg_parser->current_ip_address_option = opt->ip_addresses;
	while(cfg_parser->current_ip_address_option && cfg_parser->current_ip_address_option->next)
		cfg_parser->current_ip_address_option = cfg_parser->current_ip_address_option->next;
	cfg_parser->current_allow_notify = 0;
	cfg_parser->current_request_xfr = 0;
	cfg_parser->current_notify = 0;
	cfg_parser->current_provide_xfr = 0;

	in = fopen(cfg_parser->filename, "r");
	if(!in) {
		fprintf(stderr, "Could not open %s: %s\n", file, strerror(errno));
		return 0;
	}
	c_in = in;
	c_parse();
	fclose(in);

	if(cfg_parser->current_pattern) {
		if(!cfg_parser->current_pattern->pname)
			c_error("last pattern has no name");
		else {
			if(!nsd_options_insert_pattern(cfg_parser->opt,
				cfg_parser->current_pattern))
				c_error("duplicate pattern");
		}
	}
	if(cfg_parser->current_zone) {
		if(!cfg_parser->current_zone->name)
			c_error("last zone has no name");
		else {
			if(!nsd_options_insert_zone(opt,
				cfg_parser->current_zone))
				c_error("duplicate zone");
		}
		if(!cfg_parser->current_zone->pattern)
			c_error("last zone has no pattern");
		if(!cfg_parser->current_zone->pattern->zonefile)
			c_error("last zone pattern has no zonefile");
	}
	if(opt->keys)
	{
		if(!opt->keys->name)
			c_error("last key has no name");
		if(!opt->keys->algorithm)
			c_error("last key has no algorithm");
		if(!opt->keys->secret)
			c_error("last key has no secret blob");
	}
	RBTREE_FOR(pat, pattern_options_t*, opt->patterns)
	{
		/* lookup keys for acls */
		for(acl=pat->allow_notify; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked)
				continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options)
				c_error_msg("key %s in pattern %s could not be found",
					acl->key_name, pat->pname);
		}
		for(acl=pat->notify; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked)
				continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options)
				c_error_msg("key %s in pattern %s could not be found",
					acl->key_name, pat->pname);
		}
		for(acl=pat->request_xfr; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked)
				continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options)
				c_error_msg("key %s in pattern %s could not be found",
					acl->key_name, pat->pname);
		}
		for(acl=pat->provide_xfr; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked)
				continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options)
				c_error_msg("key %s in pattern %s could not be found",
					acl->key_name, pat->pname);
		}
	}

	if(cfg_parser->errors > 0)
	{
        	fprintf(stderr, "read %s failed: %d errors in configuration file\n",
			cfg_parser->filename,
			cfg_parser->errors);
		return 0;
	}
	return 1;
}

void c_error_va_list(const char *fmt, va_list args)
{
	cfg_parser->errors++;
        fprintf(stderr, "%s:%d: error: ", cfg_parser->filename,
		cfg_parser->line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

void c_error_msg(const char* fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        c_error_va_list(fmt, args);
        va_end(args);
}

void c_error(const char *str)
{
	cfg_parser->errors++;
        fprintf(stderr, "%s:%d: error: %s\n", cfg_parser->filename,
		cfg_parser->line, str);
}

int c_wrap()
{
        return 1;
}

zone_options_t* zone_options_create(region_type* region)
{
	zone_options_t* zone;
	zone = (zone_options_t*)region_alloc(region, sizeof(zone_options_t));
	zone->node = *RBTREE_NULL;
	zone->name = 0;
	zone->pattern = 0;
	zone->part_of_config = 0;
	return zone;
}

pattern_options_t* pattern_options_create(region_type* region)
{
	pattern_options_t* p;
	p = (pattern_options_t*)region_alloc(region, sizeof(pattern_options_t));
	p->node = *RBTREE_NULL;
	p->pname = 0;
	p->zonefile = 0;
	p->allow_notify = 0;
	p->request_xfr = 0;
	p->notify = 0;
	p->provide_xfr = 0;
	p->outgoing_interface = 0;
	p->notify_retry = 5;
	p->notify_retry_is_default = 1;
	p->allow_axfr_fallback = 1;
	p->allow_axfr_fallback_is_default = 1;
	p->implicit = 0;
	return p;
}

key_options_t* key_options_create(region_type* region)
{
	key_options_t* key;
	key = (key_options_t*)region_alloc(region, sizeof(key_options_t));
	key->name = 0;
	key->next = 0;
	key->algorithm = 0;
	key->secret = 0;
	key->tsig_key = 0;
	return key;
}

key_options_t* key_options_find(nsd_options_t* opt, const char* name)
{
	key_options_t* key = opt->keys;
	while(key) {
		if(strcmp(key->name, name)==0)
			return key;
		key = key->next;
	}
	return 0;
}

int acl_check_incoming(acl_options_t* acl, struct query* q,
	acl_options_t** reason)
{
	/* check each acl element.
	   if 1 blocked element matches - return -1.
	   if any element matches - return number.
	   else return -1. */
	int found_match = -1;
	int number = 0;
	acl_options_t* match = 0;

	if(reason)
		*reason = NULL;

	while(acl)
	{
		DEBUG(DEBUG_XFRD,2, (LOG_INFO, "testing acl %s %s",
			acl->ip_address_spec, acl->nokey?"NOKEY":
			(acl->blocked?"BLOCKED":acl->key_name)));
		if(acl_addr_matches(acl, q) && acl_key_matches(acl, q)) {
			if(!match)
			{
				match = acl; /* remember first match */
				found_match=number;
			}
			if(acl->blocked) {
				if(reason)
					*reason = acl;
				return -1;
			}
		}
		number++;
		acl = acl->next;
	}

	if(reason)
		*reason = match;
	return found_match;
}

int acl_addr_matches(acl_options_t* acl, struct query* q)
{
	if(acl->is_ipv6)
	{
#ifdef INET6
		struct sockaddr_storage* addr_storage = (struct sockaddr_storage*)&q->addr;
		struct sockaddr_in6* addr = (struct sockaddr_in6*)&q->addr;
		if(addr_storage->ss_family != AF_INET6)
			return 0;
		if(acl->port != 0 && acl->port != ntohs(addr->sin6_port))
			return 0;
		switch(acl->rangetype) {
		case acl_range_mask:
		case acl_range_subnet:
			if(!acl_addr_match_mask((uint32_t*)&acl->addr.addr6, (uint32_t*)&addr->sin6_addr,
				(uint32_t*)&acl->range_mask.addr6, sizeof(struct in6_addr)))
				return 0;
			break;
		case acl_range_minmax:
			if(!acl_addr_match_range((uint32_t*)&acl->addr.addr6, (uint32_t*)&addr->sin6_addr,
				(uint32_t*)&acl->range_mask.addr6, sizeof(struct in6_addr)))
				return 0;
			break;
		case acl_range_single:
		default:
			if(memcmp(&addr->sin6_addr, &acl->addr.addr6,
				sizeof(struct in6_addr)) != 0)
				return 0;
			break;
		}
		return 1;
#else
		return 0; /* no inet6, no match */
#endif
	}
	else
	{
		struct sockaddr_in* addr = (struct sockaddr_in*)&q->addr;
		if(addr->sin_family != AF_INET)
			return 0;
		if(acl->port != 0 && acl->port != ntohs(addr->sin_port))
			return 0;
		switch(acl->rangetype) {
		case acl_range_mask:
		case acl_range_subnet:
			if(!acl_addr_match_mask((uint32_t*)&acl->addr.addr, (uint32_t*)&addr->sin_addr,
				(uint32_t*)&acl->range_mask.addr, sizeof(struct in_addr)))
				return 0;
			break;
		case acl_range_minmax:
			if(!acl_addr_match_range((uint32_t*)&acl->addr.addr, (uint32_t*)&addr->sin_addr,
				(uint32_t*)&acl->range_mask.addr, sizeof(struct in_addr)))
				return 0;
			break;
		case acl_range_single:
		default:
			if(memcmp(&addr->sin_addr, &acl->addr.addr,
				sizeof(struct in_addr)) != 0)
				return 0;
			break;
		}
		return 1;
	}
	/* ENOTREACH */
	return 0;
}

int acl_addr_match_mask(uint32_t* a, uint32_t* b, uint32_t* mask, size_t sz)
{
	size_t i;
#ifndef NDEBUG
	assert(sz % 4 == 0);
#endif
	sz /= 4;
	for(i=0; i<sz; ++i)
	{
		if(((*a++)&*mask) != ((*b++)&*mask))
			return 0;
		++mask;
	}
	return 1;
}

int acl_addr_match_range(uint32_t* minval, uint32_t* x, uint32_t* maxval, size_t sz)
{
	size_t i;
	uint8_t checkmin = 1, checkmax = 1;
#ifndef NDEBUG
	assert(sz % 4 == 0);
#endif
	/* check treats x as one huge number */
	sz /= 4;
	for(i=0; i<sz; ++i)
	{
		/* if outside bounds, we are done */
		if(checkmin)
			if(minval[i] > x[i])
				return 0;
		if(checkmax)
			if(maxval[i] < x[i])
				return 0;
		/* if x is equal to a bound, that bound needs further checks */
		if(checkmin && minval[i]!=x[i])
			checkmin = 0;
		if(checkmax && maxval[i]!=x[i])
			checkmax = 0;
		if(!checkmin && !checkmax)
			return 1; /* will always match */
	}
	return 1;
}

int acl_key_matches(acl_options_t* acl, struct query* q)
{
	if(acl->blocked)
		return 1;
	if(acl->nokey) {
		if(q->tsig.status == TSIG_NOT_PRESENT)
			return 1;
		return 0;
	}
	/* check name of tsig key */
	if(q->tsig.status != TSIG_OK) {
		DEBUG(DEBUG_XFRD,2, (LOG_INFO, "keymatch fail query has no TSIG"));
		return 0; /* query has no TSIG */
	}
	if(q->tsig.error_code != TSIG_ERROR_NOERROR) {
		DEBUG(DEBUG_XFRD,2, (LOG_INFO, "keymatch fail, tsig has error"));
		return 0; /* some tsig error */
	}
	if(!acl->key_options->tsig_key) {
		DEBUG(DEBUG_XFRD,2, (LOG_INFO, "keymatch fail no config"));
		return 0; /* key not properly configged */
	}
	if(dname_compare(q->tsig.key_name,
		acl->key_options->tsig_key->name) != 0) {
		DEBUG(DEBUG_XFRD,2, (LOG_INFO, "keymatch fail wrong key name"));
		return 0; /* wrong key name */
	}
	if(tsig_strlowercmp(q->tsig.algorithm->short_name,
		acl->key_options->algorithm) != 0) {
		DEBUG(DEBUG_XFRD,2, (LOG_ERR, "query tsig wrong algorithm"));
		return 0; /* no such algo */
	}
	return 1;
}

int
acl_same_host(acl_options_t* a, acl_options_t* b)
{
	if(a->is_ipv6 && !b->is_ipv6)
		return 0;
	if(!a->is_ipv6 && b->is_ipv6)
		return 0;
	if(a->port != b->port)
		return 0;
	if(a->rangetype != b->rangetype)
		return 0;
	if(!a->is_ipv6) {
		if(memcmp(&a->addr.addr, &b->addr.addr,
		   sizeof(struct in_addr)) != 0)
			return 0;
		if(a->rangetype != acl_range_single &&
		   memcmp(&a->range_mask.addr, &b->range_mask.addr,
		   sizeof(struct in_addr)) != 0)
			return 0;
	} else {
#ifdef INET6
		if(memcmp(&a->addr.addr6, &b->addr.addr6,
		   sizeof(struct in6_addr)) != 0)
			return 0;
		if(a->rangetype != acl_range_single &&
		   memcmp(&a->range_mask.addr6, &b->range_mask.addr6,
		   sizeof(struct in6_addr)) != 0)
			return 0;
#else
		return 0;
#endif
	}
	return 1;
}

#if defined(HAVE_SSL)
void key_options_tsig_add(nsd_options_t* opt)
{
	key_options_t* optkey;
	uint8_t data[4000];
	tsig_key_type* tsigkey;
	const dname_type* dname;
	int size;

	for(optkey = opt->keys; optkey; optkey = optkey->next)
	{
		dname = dname_parse(opt->region, optkey->name);
		if(!dname) {
			log_msg(LOG_ERR, "Failed to parse tsig key name %s", optkey->name);
			continue;
		}
		size = b64_pton(optkey->secret, data, sizeof(data));
		if(size == -1) {
			log_msg(LOG_ERR, "Failed to parse tsig key data %s", optkey->name);
			continue;
		}
		tsigkey = (tsig_key_type *) region_alloc(opt->region, sizeof(tsig_key_type));
		tsigkey->name = dname;
		tsigkey->size = size;
		tsigkey->data = (uint8_t *) region_alloc_init(opt->region, data, tsigkey->size);
		tsig_add_key(tsigkey);
		optkey->tsig_key = tsigkey;
	}
}
#endif

int zone_is_slave(zone_options_t* opt)
{
	return opt && opt->pattern && opt->pattern->request_xfr != 0;
}

/* get a character in string (or replacement char if not long enough) */
static const char*
get_char(const char* str, size_t i)
{
	static char res[2];
	if(i >= strlen(str))
		return ".";
	res[0] = str[i];
	res[1] = 0;
	return res;
}
/* get end label of the zone name (or .) */
static const char*
get_end_label(zone_options_t* zone, int i)
{
	const dname_type* d = (const dname_type*)zone->node.key;
	if(i >= d->label_count) {
		return ".";
	}
	return wirelabel2str((uint8_t*)dname_label(d, i));
}
/* replace occurrences of one with two */
void replace_str(char* str, size_t len, const char* one, const char* two)
{
	char* pos;
	char* at = str;
	while( (pos=strstr(at, one)) ) {
		if(strlen(str)+strlen(two)-strlen(one) >= len)
			return; /* no more space to replace */
		/* stuff before pos is fine */
		/* move the stuff after pos to make space for two, add
		 * one to length of remainder to also copy the 0 byte end */
		memmove(pos+strlen(two), pos+strlen(one),
			strlen(pos+strlen(one))+1);
		/* copy in two */
		memmove(pos, two, strlen(two));
		/* at is end of the newly inserted two (avoids recursion if
		 * two contains one) */
		at = pos+strlen(two);
	}
}

const char* config_make_zonefile(zone_options_t* zone)
{
	static char f[1024];
	/* if not a template, return as-is */
	if(!strchr(zone->pattern->zonefile, '%'))
		return zone->pattern->zonefile;
	strlcpy(f, zone->pattern->zonefile, sizeof(f));
	if(strstr(f, "%1"))
		replace_str(f, sizeof(f), "%1", get_char(zone->name, 0));
	if(strstr(f, "%2"))
		replace_str(f, sizeof(f), "%2", get_char(zone->name, 1));
	if(strstr(f, "%3"))
		replace_str(f, sizeof(f), "%3", get_char(zone->name, 2));
	if(strstr(f, "%z"))
		replace_str(f, sizeof(f), "%z", get_end_label(zone, 1));
	if(strstr(f, "%y"))
		replace_str(f, sizeof(f), "%y", get_end_label(zone, 2));
	if(strstr(f, "%x"))
		replace_str(f, sizeof(f), "%x", get_end_label(zone, 3));
	if(strstr(f, "%s"))
		replace_str(f, sizeof(f), "%s", zone->name);
	return f;
}

zone_options_t* zone_options_find(nsd_options_t* opt, const struct dname* apex)
{
	return (zone_options_t*) rbtree_search(opt->zone_options, apex);
}

acl_options_t*
acl_find_num(acl_options_t* acl, int num)
{
	int count = num;
	if(num < 0)
		return 0;
	while(acl && count > 0) {
		acl = acl->next;
		count--;
	}
	if(count == 0)
		return acl;
	return 0;
}

/* true if ipv6 address, false if ipv4 */
int parse_acl_is_ipv6(const char* p)
{
	/* see if addr is ipv6 or ipv4 -- by : and . */
	while(*p) {
		if(*p == '.') return 0;
		if(*p == ':') return 1;
		++p;
	}
	return 0;
}

/* returns range type. mask is the 2nd part of the range */
int parse_acl_range_type(char* ip, char** mask)
{
	char *p;
	if((p=strchr(ip, '&'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_mask;
	}
	if((p=strchr(ip, '/'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_subnet;
	}
	if((p=strchr(ip, '-'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_minmax;
	}
	*mask = 0;
	return acl_range_single;
}

/* parses subnet mask, fills 0 mask as well */
void parse_acl_range_subnet(char* p, void* addr, int maxbits)
{
	int subnet_bits = atoi(p);
	uint8_t* addr_bytes = (uint8_t*)addr;
	if(subnet_bits == 0 && strcmp(p, "0")!=0) {
		c_error_msg("bad subnet range '%s'", p);
		return;
	}
	if(subnet_bits < 0 || subnet_bits > maxbits) {
		c_error_msg("subnet of %d bits out of range [0..%d]", subnet_bits, maxbits);
		return;
	}
	/* fill addr with n bits of 1s (struct has been zeroed) */
	while(subnet_bits >= 8) {
		*addr_bytes++ = 0xff;
		subnet_bits -= 8;
	}
	if(subnet_bits > 0) {
		uint8_t shifts[] = {0x0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
		*addr_bytes = shifts[subnet_bits];
	}
}

acl_options_t* parse_acl_info(region_type* region, char* ip, const char* key)
{
	char* p;
	acl_options_t* acl = (acl_options_t*)region_alloc(region, sizeof(acl_options_t));
	acl->next = 0;
	/* ip */
	acl->ip_address_spec = region_strdup(region, ip);
	acl->use_axfr_only = 0;
	acl->allow_udp = 0;
	acl->ixfr_disabled = 0;
	acl->key_options = 0;
	acl->is_ipv6 = 0;
	acl->port = 0;
	memset(&acl->addr, 0, sizeof(union acl_addr_storage));
	memset(&acl->range_mask, 0, sizeof(union acl_addr_storage));
	if((p=strrchr(ip, '@'))!=0) {
		if(atoi(p+1) == 0) c_error("expected port number after '@'");
		else acl->port = atoi(p+1);
		*p=0;
	}
	acl->rangetype = parse_acl_range_type(ip, &p);
	if(parse_acl_is_ipv6(ip)) {
		acl->is_ipv6 = 1;
#ifdef INET6
		if(inet_pton(AF_INET6, ip, &acl->addr.addr6) != 1)
			c_error_msg("Bad ip6 address '%s'", ip);
		if(acl->rangetype==acl_range_mask || acl->rangetype==acl_range_minmax)
			if(inet_pton(AF_INET6, p, &acl->range_mask.addr6) != 1)
				c_error_msg("Bad ip6 address mask '%s'", p);
		if(acl->rangetype==acl_range_subnet)
			parse_acl_range_subnet(p, &acl->range_mask.addr6, 128);
#else
		c_error_msg("encountered IPv6 address '%s'.", ip);
#endif /* INET6 */
	} else {
		acl->is_ipv6 = 0;
		if(inet_pton(AF_INET, ip, &acl->addr.addr) != 1)
			c_error_msg("Bad ip4 address '%s'", ip);
		if(acl->rangetype==acl_range_mask || acl->rangetype==acl_range_minmax)
			if(inet_pton(AF_INET, p, &acl->range_mask.addr) != 1)
				c_error_msg("Bad ip4 address mask '%s'", p);
		if(acl->rangetype==acl_range_subnet)
			parse_acl_range_subnet(p, &acl->range_mask.addr, 32);
	}

	/* key */
	if(strcmp(key, "NOKEY")==0) {
		acl->nokey = 1;
		acl->blocked = 0;
		acl->key_name = 0;
	} else if(strcmp(key, "BLOCKED")==0) {
		acl->nokey = 0;
		acl->blocked = 1;
		acl->key_name = 0;
	} else {
		acl->nokey = 0;
		acl->blocked = 0;
		acl->key_name = region_strdup(region, key);
	}
	return acl;
}

/* copy acl list at end of parser start, update current */
static void append_acl(acl_options_t** start, acl_options_t** cur,
	acl_options_t* list)
{
	while(list) {
		acl_options_t* acl = region_alloc_init(cfg_parser->opt->region,
			list, sizeof(*list));
		acl->next = NULL;
		if(*start)
			(*cur)->next = acl;
		else	*start = acl;
		*cur = acl;
		list = list->next;
	}
}

void config_apply_pattern(const char* name)
{
	/* find the pattern */
	pattern_options_t* pat = (pattern_options_t*)rbtree_search(
		cfg_parser->opt->patterns, name);
	pattern_options_t* a = cfg_parser->current_pattern;
	if(!pat) {
		c_error_msg("could not find pattern %s", name);
		return;
	}

	/* apply settings */
	if(pat->zonefile)
		a->zonefile = region_strdup(cfg_parser->opt->region,
			pat->zonefile);
	if(!pat->allow_axfr_fallback_is_default)
		a->allow_axfr_fallback = pat->allow_axfr_fallback;
	if(!pat->notify_retry_is_default)
		a->notify_retry = pat->notify_retry;
	/* append acl items */
	append_acl(&a->allow_notify, &cfg_parser->current_allow_notify,
		pat->allow_notify);
	append_acl(&a->request_xfr, &cfg_parser->current_request_xfr,
		pat->request_xfr);
	append_acl(&a->notify, &cfg_parser->current_notify, pat->notify);
	append_acl(&a->provide_xfr, &cfg_parser->current_provide_xfr,
		pat->provide_xfr);
	append_acl(&a->outgoing_interface, &cfg_parser->
		current_outgoing_interface, pat->outgoing_interface);
}

void nsd_options_destroy(nsd_options_t* opt)
{
	region_destroy(opt->region);
}
