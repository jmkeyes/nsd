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

#include "answer.h"
#include "dname.h"
#include "dns.h"
#include "query.h"
#include "rdata.h"
#include "region-allocator.h"
#include "tsig.h"
#include "util.h"
#include "zonec.h"

/*
 * Exit codes are based on named-xfer for now.  See ns_defs.h in
 * bind8.
 */
enum nsd_xfer_exit_codes
{
	XFER_UPTODATE = 0,
	XFER_SUCCESS  = 1,
	XFER_FAIL     = 3
};

extern char *optarg;
extern int optind;

static uint16_t init_query(query_type *q, const dname_type *dname,
			   uint16_t type, uint16_t klass);
static int read_rr_from_packet(region_type *region, domain_table_type *owners,
			       buffer_type *packet, rr_section_type section,
			       rr_type *result);

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
	exit(XFER_FAIL);
}


/*
 * Log a warning message.
 */
static void warning(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
static void
warning(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_WARNING, format, args);
	va_end(args);
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
	exit(XFER_FAIL);
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
print_rdata(buffer_type *output, rrtype_descriptor_type *descriptor,
	    rr_type *record)
{
	size_t i;
	size_t saved_position = buffer_position(output);
	
	for (i = 0; i < record->rdata_count; ++i) {
		if (descriptor->type == TYPE_SOA && i == 2) {
			buffer_printf(output, " (\n\t\t");
		}
		buffer_printf(output, " ");
		if (!rdata_atom_to_string(output, descriptor->zoneformat[i],
					  record->rdatas[i]))
		{
			buffer_set_position(output, saved_position);
			return 0;
		}
	}
	if (descriptor->type == TYPE_SOA) {
		buffer_printf(output, ")");
	}
	
	return 1;
}

static int
print_rr(region_type *region, FILE *out, rr_type *record)
{
	buffer_type *output = buffer_create(region, 1000);
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(record->type);
	int result;
	
	buffer_printf(output, "%s %lu %s %s",
		      dname_to_string(domain_dname(record->owner)),
		      (unsigned long) record->ttl,
		      rrclass_to_string(record->klass),
		      rrtype_to_string(record->type));

	result = print_rdata(output, descriptor, record);
	if (!result) {
		/*
		 * Some RDATA failed, so print the record's RDATA in
		 * unknown format.
		 */
		abort();
/* 		buffer_printf(output, " "); */
/* 		result = rdata_to_string(output, RDATA_ZF_UNKNOWN, packet); */
	}
	
	if (result) {
		buffer_printf(output, "\n");
		buffer_flip(output);
		fwrite(buffer_current(output), buffer_remaining(output), 1,
		       out);
		fflush(out);
	}
	
	return result;
}

	
static int
parse_response(struct query *q, FILE *out, int first, int *done)
{
	region_type *rr_region = region_create(xalloc, free);
	size_t rr_count;

	size_t qdcount = QDCOUNT(q);
	size_t ancount = ANCOUNT(q);

	rr_type record;

	for (rr_count = 0; rr_count < qdcount + ancount; ++rr_count) {
		domain_table_type *owners = domain_table_create(rr_region);
		
		if (!read_rr_from_packet(
			    rr_region, owners, q->packet,
			    rr_count < qdcount ? QUESTION_SECTION : ANSWER_SECTION,
			    &record))
		{
			error("bad RR");
			region_destroy(rr_region);
			return 0;
		}

		if (rr_count >= qdcount) {
			if (first && (record.type != TYPE_SOA || record.klass != CLASS_IN)) {
				error("First RR is not SOA, but %u", record.type);
				region_destroy(rr_region);
				return 0;
			} else if (!first && record.type == TYPE_SOA) {
				*done = 1;
				break;
			}

			first = 0;
			if (!print_rr(rr_region, out, &record)) {
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
read_rr_from_packet(region_type *region, domain_table_type *owners,
		    buffer_type *packet, rr_section_type section,
		    rr_type *result)
{
	const dname_type *owner;
	uint16_t rdlength;
	ssize_t rdata_count;
	rdata_atom_type *rdatas;
	
	owner = dname_make_from_packet(region, packet, 1, 1);
	if (!owner || !buffer_available(packet, 2*sizeof(uint16_t))) {
		return 0;
	}

	result->owner = domain_table_insert(owners, owner);
	result->type = buffer_read_u16(packet);
	result->klass = buffer_read_u16(packet);

	if (section == QUESTION_SECTION) {
		result->ttl = 0;
		result->rdata_count = 0;
		result->rdatas = NULL;
		return 1;
	} else if (!buffer_available(packet, sizeof(uint32_t) + sizeof(uint16_t))) {
		return 0;
	}
	
	result->ttl = buffer_read_u32(packet);
	rdlength = buffer_read_u16(packet);
	
	if (!buffer_available(packet, rdlength)) {
		return 0;
	}

	rdata_count = rdata_wireformat_to_rdata_atoms(
		region, owners, result->type, rdlength, packet, &rdatas);
	if (rdata_count == -1) {
		return 0;
	}
	result->rdata_count = rdata_count;
	result->rdatas = rdatas;
	
	return 1;
}

/*
 * Query the server for the zone serial. Return 1 if the zone serial
 * is higher than the current serial, 0 if the zone serial is lower or
 * equal to the current serial, and -1 on error.
 *
 * On success, the zone serial is returned in ZONE_SERIAL.
 */
static int
check_serial(int s, struct query *q, const dname_type *zone,
	     const uint32_t current_serial, uint32_t *zone_serial)
{
	region_type *local;
	uint16_t query_id;
	uint16_t i;
	domain_table_type *owners;
	rr_type record;
	
	query_id = init_query(q, zone, TYPE_SOA, CLASS_IN);
	
	if (!send_query(s, q)) {
		return -1;
	}
	if (!receive_response(s, q)) {
		return -1;
	}

	if (buffer_limit(q->packet) <= QHEADERSZ) {
		error("response size (%d) is too small",
		      (int) buffer_limit(q->packet));
		return -1;
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
	
	if (QDCOUNT(q) != 1) {
		error("question section count not equal to 1");
		return -1;
	}
	
	if (ANCOUNT(q) == 0) {
		error("answer section is empty");
		return -1;
	}

	buffer_skip(q->packet, QHEADERSZ);

	local = region_create(xalloc, free);
	owners = domain_table_create(local);
	
	/* Skip question records. */
	for (i = 0; i < QDCOUNT(q); ++i) {
		if (!read_rr_from_packet(local, owners, q->packet, QUESTION_SECTION, &record)) {
			error("bad RR in question section");
			region_destroy(local);
			return -1;
		}

		if (dname_compare(zone, domain_dname(record.owner)) != 0
		    || record.type != TYPE_SOA
		    || record.klass != CLASS_IN)
		{
			error("response does not match query");
			region_destroy(local);
			return -1;
		}
	}
	
	/* Find the SOA record in the response.  */
	for (i = 0; i < ANCOUNT(q); ++i) {
		if (!read_rr_from_packet(local, owners, q->packet, ANSWER_SECTION, &record)) {
			error("bad RR in answer section");
			region_destroy(local);
			return -1;
		}

		if (dname_compare(zone, domain_dname(record.owner)) == 0
		    && record.type == TYPE_SOA
		    && record.klass == CLASS_IN)
		{
			assert(record.rdata_count == 7);
			assert(rdata_atom_size(record.rdatas[2]) == 4);
			*zone_serial = read_uint32(rdata_atom_data(record.rdatas[2]));
			region_destroy(local);
			return *zone_serial > current_serial;
		}
	}

	error("SOA not found in answer");
	region_destroy(local);
	return -1;
}

static int
axfr(int s, struct query *q, const dname_type *zone, FILE *out)
{
	int done = 0;
	int first = 1;
	uint16_t query_id;
	
	assert(q->maxlen <= QIOBUFSZ);
	
	query_id = init_query(q, zone, TYPE_AXFR, CLASS_IN);

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
	}
	return 1;
}

static uint16_t
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

	return ID(q);
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
	uint32_t current_serial = 0;
	const char *port = TCP_PORT;
	region_type *region = region_create(xalloc, free);
	int default_family = DEFAULT_AI_FAMILY;
	FILE *zone_file;
	
	log_init("nsd-xfer");

	srandom((unsigned long) getpid() * (unsigned long) time(NULL));

#ifdef TSIG
	if (!tsig_init(region)) {
		error("TSIG initialization failed");
	}
#endif
	
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

	if (serial) {
		const char *t;
		current_serial = strtottl(serial, &t);
		if (*t != '\0') {
			error("bad serial '%s'\n", serial);
			exit(XFER_FAIL);
		}
	}
	
	/* Initialize the query */
	memset(&q, 0, sizeof(struct query));
	q.addrlen = sizeof(q.addr);
	q.packet = buffer_create(region, QIOBUFSZ);
	q.maxlen = MAX_PACKET_SIZE;

	for (; *argv; ++argv) {
		/* Try each server separately until one succeeds.  */
		int rc;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		rc = getaddrinfo(*argv, port, &hints, &res0);
		if (rc) {
			warning("skipping bad address %s: %s\n",
				*argv,
				gai_strerror(rc));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			uint32_t zone_serial = -1;
			int s;
			
			if (res->ai_addrlen > sizeof(q.addr))
				continue;

			s = socket(res->ai_family, res->ai_socktype,
				   res->ai_protocol);
			if (s == -1)
				continue;

			if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
				warning("cannot connect to %s: %s\n",
					*argv,
					strerror(errno));
				close(s);
				if (!res->ai_next) {
					error("failed to connect to master servers");
				}
				continue;
			}
			
			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

			rc = check_serial(s, &q, zone, current_serial,
					  &zone_serial);
			if (rc == -1) {
				close(s);
				continue;
			}

			printf("Current serial %lu, zone serial %lu\n",
			       (unsigned long) current_serial,
			       (unsigned long) zone_serial);

			if (rc == 0) {
				printf("Zone up-to-date, done.\n");
				close(s);
				exit(XFER_UPTODATE);
			} else if (rc > 0) {
				printf("Transferring zone.\n");
				
				zone_file = fopen(file, "w");
				if (!zone_file) {
					error("cannot open or create zone file '%s' for writing: %s",
					      file, strerror(errno));
					close(s);
					exit(XFER_FAIL);
				}
	
				if (axfr(s, &q, zone, zone_file)) {
					/* AXFR succeeded, done.  */
					fclose(zone_file);
					close(s);
					exit(XFER_SUCCESS);
				}
			}
			
			close(s);
		}

		freeaddrinfo(res0);
	}

	exit(0);
}
