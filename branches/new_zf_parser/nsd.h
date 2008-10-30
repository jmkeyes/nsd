/*
 * $Id: nsd.h,v 1.21 2002/02/19 14:25:11 alexis Exp $
 *
 * nsd.h -- nsd(8) definitions and prototypes
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

#ifndef	_NSD_H_
#define	_NSD_H_

#if !defined(__P)
#	if defined(__STDC__)
#		define __P(protos)     protos          /* full-blown ANSI C */
# 	else
# 		define __P(protos)
# 	endif
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "dns.h"
#include "namedb.h"
#include "query.h"

#define	NSD_RUN	0
#define	NSD_RELOAD 1
#define	NSD_SHUTDOWN 2

#ifdef	DEBUG

#define	CF_DBFILE	"nsd.db"
#define	CF_PIDFILE	"nsd.pid"
#define	CF_TCP_MAX_CONNECTIONS	8
#define	CF_TCP_PORT		4096
#define	CF_TCP_MAX_MESSAGE_LEN	16384
#define	CF_UDP_PORT		4096
#define	CF_UDP_MAX_MESSAGE_LEN	512

#else

#define	CF_DBFILE	"/var/db/nsd.db"
#define	CF_PIDFILE	"/var/run/nsd.pid"
#define	CF_TCP_MAX_CONNECTIONS	8
#define	CF_TCP_PORT		53
#define	CF_TCP_MAX_MESSAGE_LEN	16384
#define	CF_UDP_PORT		53
#define	CF_UDP_MAX_MESSAGE_LEN	512

#endif


/* NSD configuration and run-time variables */
struct	nsd {
	/* Run-time variables */
	pid_t		pid;
	int		mode;
	struct namedb	*db;
	int		debug;

	/* Configuration */
	char	*dbfile;
	char	*pidfile;

	/* TCP specific configuration */
	struct	{
		u_int16_t	port;
		int		open_conn;
		int		max_conn;
		time_t		timeout;
		size_t		max_msglen;
	} tcp;

	/* UDP specific configuration */
	struct	{
		u_int16_t	port;
		size_t		max_msglen;
	} udp;
};

void *xalloc __P((size_t));
void *xrealloc __P((void *, size_t));
int server __P((struct nsd *));
int writepid __P((pid_t, char *));
#endif	/* _NSD_H_ */