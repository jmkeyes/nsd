/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>
#include <time.h>

#include <netinet/in.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "zonec.h"

#include "dname.h"
#include "dns.h"
#include "namedb.h"
#include "options.h"
#include "rdata.h"
#include "region-allocator.h"
#include "util.h"
#include "zparser.h"

#ifndef TIMEGM
time_t timegm(struct tm *tm);
#endif /* !TIMEGM */

const dname_type *error_dname;
domain_type *error_domain;

/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);


/*
 * Allocate SIZE+sizeof(uint16_t) bytes and store SIZE in the first
 * element.  Return a pointer to the allocation.
 */
static uint16_t *
alloc_rdata(region_type *region, size_t size)
{
	uint16_t *result = region_alloc(region, sizeof(uint16_t) + size);
	*result = size;
	return result;
}

static uint16_t *
alloc_rdata_init(region_type *region, const void *data, size_t size)
{
	uint16_t *result = region_alloc(region, sizeof(uint16_t) + size);
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}

/*
 * These are parser function for generic zone file stuff.
 */
uint16_t *
zparser_conv_hex(region_type *region, const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;

	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		zc_error_prev_line("hex data exceeds maximum rdata length (%d)",
				   MAX_RDLENGTH);
	} else {
		/* the length part */
		r = alloc_rdata(region, len/2);
		t = (uint8_t *)(r + 1);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit(*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					return NULL;
				}
				++hex;
			}
			++t;
		}
	}
	return r;
}

uint16_t *
zparser_conv_time(region_type *region, const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		zc_error_prev_line("date and time is expected");
	} else {
		uint32_t l = htonl(timegm(&tm));
		r = alloc_rdata_init(region, &l, sizeof(l));
	}
	return r;
}

uint16_t *
zparser_conv_services(region_type *region, const char *protostr,
		      char *servicestr)
{
	/*
	 * Convert a protocol and a list of service port numbers
	 * (separated by spaces) in the rdata to wireformat
	 */
	uint16_t *r = NULL;
	uint8_t *p;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;

	memset(bitmap, 0, sizeof(bitmap));

	proto = getprotobyname(protostr);
	if (!proto) {
		proto = getprotobynumber(atoi(protostr));
	}
	if (!proto) {
		zc_error_prev_line("unknown protocol '%s'", protostr);
		return NULL;
	}

	for (word = strtok(servicestr, sep); word; word = strtok(NULL, sep)) {
		struct servent *service;
		int port;

		service = getservbyname(word, proto->p_name);
		if (service) {
			/* Note: ntohs not ntohl!  Strange but true.  */
			port = ntohs((uint16_t) service->s_port);
		} else {
			char *end;
			port = strtol(word, &end, 10);
			if (*end != '\0') {
				zc_error_prev_line("unknown service '%s' for protocol '%s'",
						   word, protostr);
				continue;
			}
		}

		if (port < 0 || port > 65535) {
			zc_error_prev_line("bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port)
				max_port = port;
		}
	}

	r = alloc_rdata(region, sizeof(uint8_t) + max_port / 8 + 1);
	p = (uint8_t *) (r + 1);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, *r);

	return r;
}

uint16_t *
zparser_conv_period(region_type *region, const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint16_t *r = NULL;
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = (uint32_t) strtottl(periodstr, &end);
	if (*end != 0) {
		zc_error_prev_line("time period is expected");
	} else {
		period = htonl(period);
		r = alloc_rdata_init(region, &period, sizeof(period));
	}
	return r;
}

uint16_t *
zparser_conv_short(region_type *region, const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 0));
	if (*end != 0) {
		zc_error_prev_line("integer value is expected");
	} else {
		r = alloc_rdata_init(region, &value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_long(region_type *region, const char *text)
{
	uint16_t *r = NULL;
	uint32_t value;
	char *end;

	value = htonl((uint32_t) strtol(text, &end, 0));
	if (*end != 0) {
		zc_error_prev_line("integer value is expected");
	} else {
		r = alloc_rdata_init(region, &value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_byte(region_type *region, const char *text)
{
	uint16_t *r = NULL;
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 0);
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
	} else {
		r = alloc_rdata_init(region, &value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_algorithm(region_type *region, const char *text)
{
	const lookup_table_type *alg;
	uint8_t id;

	alg = lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 0);
		if (*end != '\0') {
			zc_error_prev_line("algorithm is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(region, &id, sizeof(id));
}

uint16_t *
zparser_conv_certificate_type(region_type *region, const char *text)
{
	/* convert a algoritm string to integer */
	const lookup_table_type *type;
	uint16_t id;

	type = lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 0));
		if (end != 0) {
			zc_error_prev_line("certificate type is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(region, &id, sizeof(id));
}

uint16_t *
zparser_conv_a(region_type *region, const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		zc_error_prev_line("invalid IPv4 address '%s'", text);
	} else {
		r = alloc_rdata_init(region, &address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_aaaa(region_type *region, const char *text)
{
	uint8_t address[IP6ADDRLEN];
	uint16_t *r = NULL;

	if (inet_pton(AF_INET6, text, address) != 1) {
		zc_error_prev_line("invalid IPv6 address '%s'", text);
	} else {
		r = alloc_rdata_init(region, address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_text(region_type *region, const char *text, size_t len)
{
	uint16_t *r = NULL;

	if (len > 255) {
		zc_error_prev_line("text string is longer than 255 characters,"
				   " try splitting it into multiple parts");
	} else {
		uint8_t *p;
		r = alloc_rdata(region, len + 1);
		p = (uint8_t *) (r + 1);
		*p = len;
		memcpy(p + 1, text, len);
	}
	return r;
}

uint16_t *
zparser_conv_b64(region_type *region, const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		zc_error_prev_line("invalid base64 data");
	} else {
		r = alloc_rdata_init(region, buffer, i);
	}
	return r;
}

uint16_t *
zparser_conv_rrtype(region_type *region, const char *text)
{
	uint16_t *r = NULL;
	uint16_t type = rrtype_from_string(text);

	if (type == 0) {
		zc_error_prev_line("unrecognized RR type '%s'", text);
	} else {
		type = htons(type);
		r = alloc_rdata_init(region, &type, sizeof(type));
	}
	return r;
}

uint16_t *
zparser_conv_nxt(region_type *region, uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

	return alloc_rdata_init(region, nxtbits, last);
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t *
zparser_conv_nsec(region_type *region,
		  uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;

	/* The used windows.  */
	int used[NSEC_WINDOW_COUNT];
	/* The last byte used in each the window.  */
	int size[NSEC_WINDOW_COUNT];

	/* used[i] is the i-th window included in the nsec
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < NSEC_WINDOW_COUNT; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}

	r = alloc_rdata(region, total_size);
	ptr = (uint8_t *) (r + 1);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}

	return r;
}

/* Parse an int terminated in the specified range. */
static int
parse_int(const char *str,
	  char **end,
	  int *result,
	  const char *name,
	  int min,
	  int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		zc_error_prev_line("%s must be within the range [%d .. %d]",
				   name,
				   min,
				   max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit(*cp))
		mval = mval * 10 + hexdigit_to_int(*cp++);

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit(*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit(*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	cmval = (mval * 100) + cmval;

	for (exponent = 0; exponent < 9; exponent++)
		if (cmval < poweroften[exponent+1])
			break;

	mantissa = cmval / poweroften[exponent];
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') cp++;

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
uint16_t *
zparser_conv_loc(region_type *region, char *str)
{
	uint16_t *r;
	uint32_t *p;
	int i;
	int deg, min, secs;	/* Secs is stored times 1000.  */
	uint32_t lat = 0, lon = 0, alt = 0;
	uint8_t vszhpvp[4] = {0, 0, 0, 0};
	char *start;
	double d;


	for(;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			zc_error_prev_line("unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace(*str)) {
			zc_error_prev_line("space expected after degrees");
			return NULL;
		}
		++str;

		/* Minutes? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace(*str)) {
				zc_error_prev_line("space expected after minutes");
				return NULL;
			}
		}
		++str;

		/* Seconds? */
		if (isdigit(*str)) {
			start = str;
			if (!parse_int(str, &str, &i, "seconds", 0, 60)) {
				return NULL;
			}

			if (*str == '.' && !parse_int(str + 1, &str, &i, "seconds fraction", 0, 999)) {
				return NULL;
			}

			if (!isspace(*str)) {
				zc_error_prev_line("space expected after seconds");
				return NULL;
			}

			if (sscanf(start, "%lf", &d) != 1) {
				zc_error_prev_line("error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				zc_error_prev_line("seconds not in range 0.0 .. 6.0");
			}

			secs = (int) (d * 1000.0);
		}
		++str;

		switch(*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		default:
			zc_error_prev_line("invalid latitude/longtitude");
			return NULL;
		}
		++str;

		if (lat != 0 && lon != 0)
			break;

		if (!isspace(*str)) {
			zc_error_prev_line("space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		zc_error_prev_line("unexpected end of LOC data");
		return NULL;
	}

	if (!isspace(*str)) {
		zc_error_prev_line("space expected before altitude");
		return NULL;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	(void) strtol(str, &str, 10);
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return NULL;
		}
		if (!isspace(*str) && *str != '\0' && *str != 'm') {
			zc_error_prev_line("altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		zc_error_prev_line("altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace(*str) && *str != '\0')
		++str;

	if (sscanf(start, "%lf", &d) != 1) {
		zc_error_prev_line("error parsing altitude");
	}

	alt = 10000000 + (int32_t) (d * 100);

	if (!isspace(*str) && *str != '\0') {
		zc_error_prev_line("unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace(*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace(*str) && *str != '\0') {
			zc_error_prev_line("invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = alloc_rdata(region, 16);
	p = (uint32_t *) (r + 1);

	memcpy(p, vszhpvp, 4);
	write_uint32(p + 1, lat);
	write_uint32(p + 2, lon);
	write_uint32(p + 3, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t *
zparser_conv_apl_rdata(region_type *region, char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint16_t *r;
	uint8_t *t;
	char *end;
	long p;

	if (!colon) {
		zc_error("address family separator is missing");
		return NULL;
	}
	if (!slash) {
		zc_error("prefix separator is missing");
		return NULL;
	}

	*colon = '\0';
	*slash = '\0';

	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = htons(1);
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = htons(2);
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		zc_error("invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		zc_error("invalid address '%s'", colon + 1);
		return NULL;
	} else if (rc == -1) {
		zc_error("inet_pton failed: %s", strerror(errno));
		return NULL;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0)
		--length;


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		zc_error("prefix not in the range 0 .. %d", maximum_prefix);
		return NULL;
	} else if (*end != '\0') {
		zc_error("invalid prefix '%s'", slash + 1);
		return NULL;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = alloc_rdata(region, rdlength);
	t = (uint8_t *) (r + 1);

	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated) {
		*t |= APL_NEGATION_MASK;
	}
	t += sizeof(length);
	memcpy(t, address, length);

	return r;
}

/*
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

int32_t
zparser_ttl2int(const char *ttlstr)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	int32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		zc_error_prev_line("invalid TTL value: %s",ttlstr);
		ttl = -1;
	}

	return ttl;
}


void
zadd_rdata_wireformat(uint16_t *data)
{
	if (parser->rr.rdata_count > MAXRDATALEN) {
		zc_error_prev_line("too many rdata elements");
	} else {
		parser->rr.rdatas[parser->rr.rdata_count].is_domain = 0;
		parser->rr.rdatas[parser->rr.rdata_count].u.data = data;
		++parser->rr.rdata_count;
	}
}

void
zadd_rdata_domain(const dname_type *dname)
{
	if (parser->rr.rdata_count > MAXRDATALEN) {
		zc_error_prev_line("too many rdata elements");
	} else {
		parser->rr.rdatas[parser->rr.rdata_count].is_domain = 1;
		parser->rr.rdatas[parser->rr.rdata_count].u.dname = dname;
		++parser->rr.rdata_count;
	}
}

static int
parse_unknown_rdata(rr_type *rr, uint16_t *wireformat)
{
	buffer_type packet;
	uint16_t size = *wireformat;
	ssize_t rdata_count;
	rdata_atom_type *rdatas;

	buffer_create_from(&packet, wireformat + 1, *wireformat);
	rdata_count = rdata_wireformat_to_rdata_atoms(
		parser->region,
		parser->current_zone->domains,
		rr->type,
		size,
		&packet,
		&rdatas);
	if (rdata_count == -1) {
		zc_error_prev_line("bad unknown RDATA");
		return 0;
	}

	rr->rdata_count = rdata_count;
	rr->rdatas = rdatas;
	return 1;
}


/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */
static int
zrdatacmp(uint16_t type, rr_type *a, rr_type *b)
{
	int i = 0;

	assert(a);
	assert(b);

	/* One is shorter than another */
	if (a->rdata_count != b->rdata_count)
		return 1;

	/* Compare element by element */
	for (i = 0; i < a->rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(a->rdatas[i])
			    != rdata_atom_domain(b->rdatas[i]))
			{
				return 1;
			}
		} else {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
			{
				return 1;
			}
			if (memcmp(rdata_atom_data(a->rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])) != 0)
			{
				return 1;
			}
		}
	}

	/* Otherwise they are equal */
	return 0;
}

/*
 *
 * Opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
static int
zone_open(const char *filename, uint32_t ttl, uint16_t klass,
	  const dname_type *origin)
{
	/* Open the zone file... */
	if (strcmp(filename, "-") == 0) {
		yyin = stdin;
		filename = "<stdin>";
	} else if (!(yyin = fopen(filename, "r"))) {
		return 0;
	}

	/* Open the network database */
	setprotoent(1);
	setservent(1);

	zparser_init(filename, ttl, klass, origin);

	return 1;
}


void
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	    uint16_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;

	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}


static void
cleanup_rrset(void *r)
{
	rrset_type *rrset = (rrset_type *) r;
	if (rrset) {
		free(rrset->rrs);
	}
}

int
process_rr()
{
	rr_type rr;
	rrset_type *rrset;
	size_t max_rdlength;
	int i;
	rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(parser->rr.type);

	/* We only support IN class */
	if (parser->rr.klass != CLASS_IN) {
		zc_error_prev_line("only class IN is supported");
		return 0;
	}

	if (parser->rr.type == TYPE_SOA) {
		/*
		 * This is a SOA record, start a new zone or continue
		 * an existing one.
		 */
		parser->current_zone
			= namedb_insert_zone(parser->db, parser->rr.owner);
	}

	switch (parser->rr.type) {
	case TYPE_MD:
		zc_warning_prev_line("MD is obsolete");
		break;
	case TYPE_MF:
		zc_warning_prev_line("MF is obsolete");
		break;
	case TYPE_MB:
		zc_warning_prev_line("MB is obsolete");
		break;
	default:
		break;
	}

	if (!dname_is_subdomain(parser->rr.owner,
				domain_dname(parser->current_zone->apex)))
	{
		zc_error_prev_line("out of zone data");
		return 0;
	}

	/*
	 * Convert the data from the parser into an RR.
	 */
	rr.owner = domain_table_insert(parser->current_zone->domains,
				       parser->rr.owner);
	rr.ttl = parser->rr.ttl;
	rr.type = parser->rr.type;
	rr.klass = parser->rr.klass;
	if (parser->rr.unknown_rdata) {
		if (!parse_unknown_rdata(&rr, parser->rr.unknown_rdata)) {
			return 0;
		}
	} else {
		rr.rdata_count = parser->rr.rdata_count;
		rr.rdatas = (rdata_atom_type *) region_alloc(
			parser->region,
			rr.rdata_count * sizeof(rdata_atom_type));
		for (i = 0; i < rr.rdata_count; ++i) {
			if (parser->rr.rdatas[i].is_domain) {
				rr.rdatas[i].domain = domain_table_insert(
					parser->current_zone->domains,
					parser->rr.rdatas[i].u.dname);
			} else {
				rr.rdatas[i].data = parser->rr.rdatas[i].u.data;
			}
		}
	}

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.	*/
	max_rdlength = rdata_maximum_wireformat_size(
		descriptor, rr.rdata_count, rr.rdatas);
	if (max_rdlength > MAX_RDLENGTH) {
		zc_error_prev_line("maximum rdata length exceeds %d octets",
				   MAX_RDLENGTH);
		return 0;
	}

	/* Do we have this type of rrset already? */
	rrset = domain_find_rrset(rr.owner, rr.type);
	if (!rrset) {
		rrset = (rrset_type *) region_alloc(parser->region,
						    sizeof(rrset_type));
		rrset->rr_count = 1;
		rrset->rrs = (rr_type *) xalloc(sizeof(rr_type));
		rrset->rrs[0] = rr;

		region_add_cleanup(parser->region, cleanup_rrset, rrset);

		/* Add it */
		domain_add_rrset(rr.owner, rrset);
	} else {
		if (rr.type != TYPE_RRSIG && rrset->rrs[0].ttl != rr.ttl) {
			zc_warning_prev_line(
				"TTL does not match the TTL of the RRset");
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rr_count; ++i) {
			/* TODO: Why pass rr.type? */
			if (!zrdatacmp(rr.type, &rr, &rrset->rrs[i])) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rr_count) {
			return 0;
		}

		/* Add it... */
		rrset->rrs = (rr_type *) xrealloc(
			rrset->rrs,
			(rrset->rr_count + 1) * sizeof(rr_type));
		rrset->rrs[rrset->rr_count] = rr;
		++rrset->rr_count;
	}

#ifdef DNSSEC
	if (rr.owner == parser->current_zone->apex
	    && rr.type == TYPE_RRSIG
	    && rr_rrsig_type_covered(&rr) == TYPE_SOA)
	{
		parser->current_zone->is_secure = 1;
	}
#endif

	/* Check we have SOA */
	/* [XXX] this is dead code */
	if (parser->current_zone->soa_rrset == NULL) {
		if (rr.type != TYPE_SOA) {
			zc_error_prev_line(
				"missing SOA record on top of the zone");
		} else if (rr.owner != parser->current_zone->apex) {
			/* Can't happen.  */
			zc_error_prev_line(
				"SOA record with invalid domain name");
		} else {
			parser->current_zone->soa_rrset = rrset;
		}
	} else if (rr.type == TYPE_SOA) {
		zc_error_prev_line("duplicate SOA record discarded");
		--rrset->rr_count;
	}

	/* Is this a zone NS? */
	if (rr.type == TYPE_NS && rr.owner == parser->current_zone->apex) {
		parser->current_zone->ns_rrset = rrset;
	}
	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		printf("%ld\n", totalrrs);
	}
	++totalrrs;
	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static void
zone_read(const dname_type *name, const char *zonefile)
{
#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dname_is_root(name) == 1) {
		zc_error("not configured as a root server");
		return;
	}
#endif

	/* Open the zone file */
	if (!zone_open(zonefile, DEFAULT_TTL, CLASS_IN, name)) {
		/* cannot happen with stdin - so no fix needed for zonefile */
		fprintf(stderr, " ERR: Cannot open \'%s\': %s\n", zonefile, strerror(errno));
		return;
	}

	/* Parse and process all RRs.  */
	yyparse();

	fclose(yyin);

	fflush(stdout);
	totalerrors += parser->errors;
}

static void
usage (void)
{
	fprintf(stderr, "usage: zonec [-v|-h] [-c config-file] [-f database]\n");
	fprintf(stderr, "   or: zonec [-v|-h] -o origin -f database zone-file\n");
	fprintf(stderr, "NSD Zone Compiler\n\nSupported options:\n");
	fprintf(stderr, "  -c config-file  Specify the configuration file.\n");
	fprintf(stderr, "  -f database     Specify the database file.\n");
	fprintf(stderr, "  -h              Print this help information.\n");
	fprintf(stderr, "  -o origin       Specify the origin for ZONE-FILE, the configuration file is\n");
	fprintf(stderr, "                  ignored.\n");
	fprintf(stderr, "  -v              Be more verbose, can be specified multiple times.\n");
	fprintf(stderr, "\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);

	exit(EXIT_FAILURE);
}

extern char *optarg;
extern int optind;

int
main (int argc, char **argv)
{
	namedb_type *db;
	const dname_type *origin = NULL;
	int c;
	region_type *global_region;
	region_type *rr_region;
	const char *options_file = CONFIGFILE;
	const char *zone_file = NULL;
	const char *database_file = NULL;
	nsd_options_type *options = NULL;

	log_init("zonec");

#ifndef NDEBUG
	/* Check consistency of rrtype descriptor table.  */
	{
		int i;
		for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
			if (i != rrtype_descriptors[i].type) {
				internal_error(
					__FILE__, __LINE__,
					"error: type descriptor entry '%d' "
					"does not match type '%d', fix the "
					"definition in dns.c\n",
					i, rrtype_descriptors[i].type);
			}
		}
	}
#endif

	global_region = region_create(xalloc, free);
	rr_region = region_create(xalloc, free);
	totalerrors = 0;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "c:f:F:L:ho:v")) != -1) {
		switch (c) {
		case 'c':
			options_file = optarg;
			break;
		case 'f':
			database_file = optarg;
			break;
#ifndef NDEBUG
		case 'F':
			sscanf(optarg, "%x", &nsd_debug_facilities);
			break;
		case 'L':
			sscanf(optarg, "%d", &nsd_debug_level);
			break;
#endif /* NDEBUG */
		case 'o':
			origin = dname_parse(global_region, optarg);
			if (!origin) {
				error("origin '%s' is not domain name", optarg);
			}
			break;
		case 'v':
			++vflag;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (origin) {
		if (argc == 1) {
			zone_file = argv[0];
		} else {
			usage();
		}
	} else if (argc != 0) {
		usage();
	} else {
		options = nsd_load_config(global_region, options_file);
		if (!options) {
			error("failed to load configuration file '%s'",
			      options_file);
		}

		if (options->directory) {
			if (chdir(options->directory) == -1) {
				error("cannot change directory to '%s': %s",
				      options->directory,
				      strerror(errno));
			}
		}

		if (!database_file) {
			database_file = options->database;
		}
	}

	/* Create the database */
	db = namedb_new(database_file);
	if (!db) {
		error("error creating the database: %s\n", database_file);
	}

	parser = zparser_create(global_region, rr_region, db);

	/* Unique pointers used to mark errors.	 */
	error_dname = (dname_type *) region_alloc(global_region, 0);
	error_domain = (domain_type *) region_alloc(global_region, 0);

	if (origin) {
		/*
		 * Read a single zone file with the specified origin
		 * instead of the zone master file.
		 */
		zone_read(origin, zone_file);
	} else {
		size_t i;

		for (i = 0; i < options->zone_count; ++i) {
			nsd_options_zone_type *zone = options->zones[i];

			if (!zone) {
				continue;
			}

			if (vflag > 0) {
				log_msg(LOG_INFO,
					"reading zone '%s' from file '%s'",
					dname_to_string(zone->name, NULL),
					zone->file);
			}

			zone_read(zone->name, zone->file);
			if (vflag > 1) {
				log_msg(LOG_INFO,
					"processed %ld RRs in zone '%s'",
					totalrrs,
					dname_to_string(zone->name, NULL));
			}

			totalrrs = 0;
		}
	}

#ifndef NDEBUG
	fprintf(stderr, "global_region: ");
	region_dump_stats(global_region, stderr);
	fprintf(stderr, "\n");
	fprintf(stderr, "db->region: ");
	region_dump_stats(db->region, stderr);
	fprintf(stderr, "\n");
#endif /* NDEBUG */

	/* Close the database */
	if (namedb_save(db) != 0) {
		log_msg(LOG_ERR, "error saving the database: %s",
			strerror(errno));
		namedb_discard(db);
		exit(EXIT_FAILURE);
	}

	/* Print the total number of errors */
	if (vflag > 0 || totalerrors > 0) {
		log_msg(LOG_INFO, "done with %ld errors.", totalerrors);
	}

	/* Disable this to save some time.  */
#if 0
	region_destroy(global_region);
#endif

	exit(totalerrors > 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(EXIT_FAILURE);
}