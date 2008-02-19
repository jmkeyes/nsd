/*
 * client.h - client (nsdc) code header file
 *
 * MIEK: THIS FILE CAN GO
 * Copyright (c) 2001-2005, NLnet Labs, All right reserved
 *
 * See LICENSE for the license
 *
 */

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "query.h"

#define DEFAULT_CONTROL_TTL	0
#define DEFAULT_CONTROL_HOST	"localhost"

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

/* the following commands are understood by NSD */
enum control_msg {
	CONTROL_UNKNOWN,
	CONTROL_STATUS,
	CONTROL_VERSION
};


/* Log a warning message. */
void warning(const char *format, ...) ATTR_FORMAT(printf, 1, 2);

/* Log a error message and exit */
void
error(int exitcode, const char *format, ...);

/*
 * Read SIZE bytes from the socket into BUF.  Keep reading unless an
 * error occurs (except for EAGAIN) or EOF is reached.
 */
int read_socket(int s, void *buf, size_t size);

/*
 * Write the complete buffer to the socket, irrespective of short
 * writes or interrupts.
 */
int write_socket(int s, const void *buf, size_t size);

/*
 * Send to query through socket s
 */
int send_query(int s, query_type *q);

/*
 * print a RR to the filedescriptor *out
 * for mem allocs use *region
 */
int print_rr_region(FILE *out, region_type *region, rr_type *record);

/*
 * print the rdata of an record to a buffer 
 */
int print_rdata(buffer_type *output, 
		rrtype_descriptor_type *descriptor, 
		rr_type *record);

#endif /* _CLIENT_H_ */