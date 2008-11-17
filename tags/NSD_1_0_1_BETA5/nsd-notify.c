/*
 * $Id: nsd-notify.c,v 1.1 2002/05/30 14:56:28 alexis Exp $
 *
 * nsd-notify.c -- sends notify(rfc1996) message to a list of servers
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifdef INET6
#undef	INET6
#endif

#include "nsd.h"
#include "zf.h"

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * fprintf(stderr, ...);
 *
 */
void *
xalloc(size)
	register size_t size;
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "zonec: malloc failed: %m\n");
		exit(1);
	}
	return p;
}

void *
xrealloc(p, size)
	register void *p;
	register size_t size;
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "zonec: realloc failed: %m\n");
		exit(1);
	}
	return p;
}


int
usage()
{
	fprintf(stderr, "usage: nsd-notify -z zone servers\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int c, udp_s;
	struct	query q;
	struct sockaddr_in udp_addr;
	u_char *zone = NULL;
	u_int16_t qtype = htons(TYPE_SOA);
	u_int16_t qclass = htons(CLASS_IN);

	/* Parse the command line... */
	while((c = getopt(argc, argv, "z:")) != -1) {
		switch (c) {
		case 'z':
			if((zone = strdname(optarg, ROOT_ORIGIN)) == NULL)
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(argc == 0 || zone == NULL)
		usage();

	/* Set up UDP */
	bzero(&udp_addr, sizeof(udp_addr));
	udp_addr.sin_port = 0;
	udp_addr.sin_addr.s_addr = INADDR_ANY;
	udp_addr.sin_family = AF_INET;

	/* Make a socket... */
	if((udp_s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "cant create a socket: %s\n", strerror(errno));
		exit(1);
	}

	/* Bind it */
	if(bind(udp_s, (struct sockaddr *)&udp_addr, sizeof(struct sockaddr_in))) {
		fprintf(stderr, "cant bind the socket: %s\n", strerror(errno));
		return -1;
	}


	/* Initialize the query */
	bzero(&q, sizeof(struct query));
	query_init(&q);

	/* Setup the address */
	bzero(&q.addr, sizeof(struct sockaddr));
	q.addr.sin_port = htons(53);
	q.addr.sin_family = AF_INET;

	/* Set up the header */
	OPCODE_SET((&q), OPCODE_NOTIFY);
	ID((&q)) = random();
	AA_SET((&q));

	q.iobufptr = q.iobuf + QHEADERSZ;

	/* Add the domain name */
	if(*zone > MAXDOMAINLEN) {
		fprintf(stderr, "zone name length exceeds %d\n", MAXDOMAINLEN);
		exit(1);
	}
	bcopy(zone + 1, q.iobufptr, *zone);
	q.iobufptr += *zone;

	/* Add type & class */
	bcopy(&qtype, q.iobufptr, 2);
	q.iobufptr += 2;
	bcopy(&qclass, q.iobufptr, 2);
	q.iobufptr += 2;

	/* Set QDCOUNT=1 */
	QDCOUNT((&q)) = htons(1);

	/* WE ARE READY SEND IT OUT */

	/* Set up the target port */
	while(*argv) {
		if((q.addr.sin_addr.s_addr = inet_addr(*argv)) == -1) {
			fprintf(stderr, "skipping bad address %s\n", *argv);
		} else {
			if(sendto(udp_s, q.iobuf, q.iobufptr - q.iobuf, 0,
					(struct sockaddr *)&q.addr, sizeof(struct sockaddr_in)) == -1) {
				fprintf(stderr, "send to %s failed: %s\n", *argv, strerror(errno));
			}
		}
		argv++;
	}

	close(udp_s);
	exit(1);

}