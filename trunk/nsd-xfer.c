/*
 * nsd-xfer.c -- nsd-xfer(8).
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "query.h"
#include "region-allocator.h"
#include "tsig.h"
#include "util.h"
#include "zonec.h"

extern char *optarg;
extern int optind;

static void init_query(query_type *q, const dname_type *dname, uint16_t type,
		       uint16_t klass);

/*
 * Log an error message and exit.
 */
static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(1);
}


/*
 * Display usage information and exit.
 */
static void
usage (void)
{
	fprintf(stderr,
		"Usage: nsd-xfer [-4] [-6] [-p port] [-s serial] -z zone"
		" -f file servers...\n");
	exit(1);
}

/*
 * Write the complete buffer to the socket, irrespective of short
 * writes or interrupts.
 */
static int
write_socket(int s, const void *buf, size_t size)
{
	const char *data = buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = write(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EINTR) {
				return 0;
			} else {
				continue;
			}
		}
		total_count += count;
	}

	return 1;
}

/*
 * Read SIZE bytes from the socket into BUF.  Keep reading unless an
 * error occurs (except for EINTR) or EOF is reached.
 */
static int
read_socket(int s, void *buf, size_t size)
{
	char *data = buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = read(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EINTR) {
				return 0;
			} else {
				continue;
			}
		}
		total_count += count;
	}

	return 1;
}

static int
print_rdata(buffer_type *output, buffer_type *packet,
	    rrtype_descriptor_type *descriptor)
{
	int i;
	size_t saved_position = buffer_position(output);
	
	for (i = 0; i < descriptor->maximum; ++i) {
		if (buffer_remaining(packet) == 0) {
			if (i < descriptor->minimum) {
				error("RDATA is not complete");
				return 0;
			} else {
				break;
			}
		}

		buffer_printf(output, " ");
		if (!rdata_to_string(output, descriptor->zoneformat[i], packet)) {
			buffer_set_position(output, saved_position);
			return 0;
		}
	}
	
	return 1;
}

static int
print_rr(region_type *region, buffer_type *packet, FILE *out,
	 const dname_type *owner, uint16_t rrtype, uint16_t rrclass,
	 uint32_t rrttl, uint16_t rdlength)
{
	buffer_type *output = buffer_create(region, 1000);
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
	size_t saved_position;
	size_t saved_limit;
	int result;
	
	if (!buffer_available(packet, rdlength)) {
		error("RDATA truncated");
		return 0;
	}

	saved_limit = buffer_limit(packet);
	buffer_set_limit(packet, buffer_position(packet) + rdlength);
	
	buffer_printf(output, "%s %lu %s %s",
		      dname_to_string(owner), (unsigned long) rrttl,
		      rrclass_to_string(rrclass), rrtype_to_string(rrtype));

	saved_position = buffer_position(packet);
	result = print_rdata(output, packet, descriptor);
	if (!result) {
		/*
		 * Some RDATA failed, so print the record's RDATA in
		 * unknown format.
		 */
		buffer_set_position(packet, saved_position);
		buffer_printf(output, " ");
		result = rdata_to_string(output, RDATA_ZF_UNKNOWN, packet);
	}
	
	assert(!result || buffer_remaining(packet) == 0);
	
	if (result) {
		buffer_printf(output, "\n");
		buffer_flip(output);
		fwrite(buffer_current(output), buffer_remaining(output), 1,
		       out);
	}
	
	buffer_set_limit(packet, saved_limit);
	
	return result;
}

	
static int
parse_response(struct query *q, FILE *out, int first, int *done)
{
	region_type *rr_region = region_create(xalloc, free);
	size_t rr_count;

	size_t qdcount = QDCOUNT(q);
	size_t ancount = ANCOUNT(q);
	size_t nscount = NSCOUNT(q);
	size_t arcount = ARCOUNT(q);
	
	const dname_type *owner;
	uint16_t rrtype;
	uint16_t rrclass;
	uint32_t rrttl;
	uint16_t rdlength;

	for (rr_count = 0; rr_count < qdcount + ancount; ++rr_count) {
		owner = dname_make_from_packet(rr_region, q->packet, 0);
		if (!owner) {
			region_destroy(rr_region);
			return 0;
		}

		if (rr_count < qdcount) {
			if (!buffer_available(q->packet, 4)) {
				error("RR out of bounds 1");
				region_destroy(rr_region);
				return 0;
			}
			buffer_skip(q->packet, 4);
			continue;
		} else {
			if (!buffer_available(q->packet, 10)) {
				error("RR out of bounds 2");
				region_destroy(rr_region);
				return 0;
			}
			rrtype = buffer_read_u16(q->packet);
			rrclass = buffer_read_u16(q->packet);
			rrttl = buffer_read_u32(q->packet);
			rdlength = buffer_read_u16(q->packet);

			if (first && rrtype != TYPE_SOA) {
				error("First RR is not SOA, but %u", rrtype);
				region_destroy(rr_region);
				return 0;
			} else if (!first && rrtype == TYPE_SOA) {
				*done = 1;
				region_destroy(rr_region);
				return 1;
			}

			first = 0;
			if (!print_rr(rr_region, q->packet, out, owner, rrtype, rrclass, rrttl, rdlength)) {
				region_destroy(rr_region);
				return 0;
			}
		}

		region_free_all(rr_region);
	}

	region_destroy(rr_region);
	return 1;
}

static int
send_query(int s, struct query *q)
{
	uint16_t size = htons(buffer_remaining(q->packet));
	
	if (!write_socket(s, &size, sizeof(size))) {
		error("failed to send query size: %s", strerror(errno));
		return 0;
	}
	if (!write_socket(s, buffer_begin(q->packet), buffer_limit(q->packet)))
	{
		error("failed to send query data: %s", strerror(errno));
		return 0;
	}

	return 1;
}

static int
receive_response(int s, query_type *q)
{
	uint16_t size;
	
	buffer_clear(q->packet);
	if (!read_socket(s, &size, sizeof(size))) {
		error("failed to read response size: %s", strerror(errno));
		return 0;
	}
	size = ntohs(size);
	if (size > q->maxlen) {
		error("response size (%d) exceeds maximum (%d)",
		      (int) size, (int) q->maxlen);
		return 0;
	}
	if (!read_socket(s, buffer_begin(q->packet), size)) {
		error("failed to read response data: %s", strerror(errno));
		return 0;
	}

	buffer_set_limit(q->packet, size);
	
	return 1;
}

static int
check_serial(int s, struct query *q, const dname_type *zone,
	     const char *serial)
{
	region_type *local;
	uint16_t query_id;
	int result;
	
	init_query(q, zone, TYPE_SOA, CLASS_IN);
	query_id = ID(q);
	
	if (!send_query(s, q)) {
		return -1;
	}
	if (!receive_response(s, q)) {
		return -1;
	}

	if (buffer_limit(q->packet) <= QHEADERSZ) {
		error("response size (%d) is too small",
		      (int) buffer_limit(q->packet));
		return 0;
	}
	
	if (!QR(q)) {
		error("response is not a response");
		return -1;
	}

	if (TC(q)) {
		error("response is truncated");
		return -1;
	}
	
	if (ID(q) != query_id) {
		error("bad response id (%d), expected (%d)",
		      (int) ID(q), (int) query_id);
		return -1;
	}
	
	if (RCODE(q) != RCODE_OK) {
		error("error response %d", (int) RCODE(q));
		return -1;
	}
	
	if (QDCOUNT(q) > 1) {
		error("query section count greater than 1");
		return -1;
	}
	
	if (ANCOUNT(q) == 0) {
		error("answer section is empty");
		return -1;
	}

	buffer_skip(q->packet, QHEADERSZ);

	local = region_create(xalloc, free);

	/* Find the SOA record in the response.  */
	
	
	region_destroy(local);
	return result;
}

static int
axfr(int s, struct query *q, const dname_type *zone, FILE *out)
{
	int done = 0;
	int first = 1;
	uint16_t size;
	uint16_t query_id = ID(q);
	
	assert(q->maxlen <= QIOBUFSZ);
	
	init_query(q, zone, TYPE_AXFR, CLASS_IN);

	if (!send_query(s, q)) {
		return 0;
	}
	
	while (!done) {
		if (!receive_response(s, q)) {
			return 0;
		}
		
		if (buffer_limit(q->packet) <= QHEADERSZ) {
			error("response size (%d) is too small",
			      (int) buffer_limit(q->packet));
			return 0;
		}

		if (!QR(q)) {
			error("response is not a response");
			return 0;
		}

		if (ID(q) != query_id) {
			error("bad response id (%d), expected (%d)",
			      (int) ID(q), (int) query_id);
			return 0;
		}

		if (RCODE(q) != RCODE_OK) {
			error("error response %d", (int) RCODE(q));
			return 0;
		}

		if (QDCOUNT(q) > 1) {
			error("query section count greater than 1");
			return 0;
		}

		if (ANCOUNT(q) == 0) {
			error("answer section is empty");
			return 0;
		}

		buffer_skip(q->packet, QHEADERSZ);
		
		if (!parse_response(q, out, first, &done))
			return 0;

		first = 0;
		
		fprintf(stderr, "Received response size %d\n", (int) size);
	}
	return 1;
}

static void
init_query(query_type *q, const dname_type *dname, uint16_t type,
	   uint16_t klass)
{
	buffer_clear(q->packet);
	
	/* Set up the header */
	ID_SET(q, (uint16_t) random());
	FLAGS_SET(q, 0);
	OPCODE_SET(q, OPCODE_QUERY);
	AA_SET(q);
	QDCOUNT_SET(q, 1);
	ANCOUNT_SET(q, 0);
	NSCOUNT_SET(q, 0);
	ARCOUNT_SET(q, 0);
	buffer_skip(q->packet, QHEADERSZ);

	/* The question record.  */
	buffer_write(q->packet, dname_name(dname), dname->name_size);
	buffer_write_u16(q->packet, type);
	buffer_write_u16(q->packet, klass);

	buffer_flip(q->packet);
}

int 
main (int argc, char *argv[])
{
	int c;
	struct query q;
	struct addrinfo hints, *res0, *res;
	const dname_type *zone = NULL;
	const char *file = NULL;
	const char *serial = NULL;
	const char *port = TCP_PORT;
	region_type *region = region_create(xalloc, free);
	int default_family = DEFAULT_AI_FAMILY;
	FILE *zone_file;
	
	log_init("nsd-xfer");

	srandom((unsigned long) getpid() * (unsigned long) time(NULL));

	if (!tsig_init(region)) {
		error("TSIG initialization failed");
	}
	
	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46f:hp:s:z:")) != -1) {
		switch (c) {
		case '4':
			default_family = AF_INET;
			break;
		case '6':
#ifdef INET6
			default_family = AF_INET6;
#else /* !INET6 */
			error("IPv6 support not enabled.");
#endif /* !INET6 */
			break;
		case 'f':
			file = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'p':
			port = optarg;
			break;
		case 's':
			serial = optarg;
			break;
		case 'z':
			zone = dname_parse(region, optarg, NULL);
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0 || !zone || !file)
		usage();

	zone_file = fopen(file, "w");
	if (!zone_file) {
		error("cannot open zone file '%s' for writing: %s",
		      file, strerror(errno));
		exit(1);
	}
	
	/* Initialize the query */
	memset(&q, 0, sizeof(struct query));
	q.addrlen = sizeof(q.addr);
	q.packet = buffer_create(region, QIOBUFSZ);
	q.maxlen = MAX_PACKET_SIZE;

	for (; *argv; ++argv) {
		/* Try each server separately until one succeeds.  */
		int error;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		error = getaddrinfo(*argv, port, &hints, &res0);
		if (error) {
			fprintf(stderr, "skipping bad address %s: %s\n", *argv,
				gai_strerror(error));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			int s;
			if (res->ai_addrlen > sizeof(q.addr))
				continue;

			s = socket(res->ai_family, res->ai_socktype,
				   res->ai_protocol);
			if (s == -1)
				continue;

			if (connect(s, res->ai_addr, res->ai_addrlen) < 0)
				continue;
			
			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

			if (axfr(s, &q, zone, zone_file)) {
				/* AXFR succeeded, done.  */
				fclose(zone_file);
				exit(0);
			}
			
			close(s);
		}

		freeaddrinfo(res0);
	}

	exit(0);
}
