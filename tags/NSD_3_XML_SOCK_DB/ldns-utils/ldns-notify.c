/* 
 * ldns-notify.c - ldns-notify(8)
 * 
 * Copyright (c) 2001-2005, NLnet Labs, All right reserved
 *
 * See LICENSE for the license
 *
 * send a notify packet to a server
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

/* nsd includes */
#include <nsd.h>
#include <options.h>

/* ldns */
#include <ldns/dns.h>

/* ldns-util specific includes */
#include "ldns-nsd-glue.h"

static void
usage(void)
{
	fprintf(stderr, "usage: nsd-notify [-h] [-v] [-c config-file] -z zone\n");
	fprintf(stderr, "NSD notify utility\n\n");
	fprintf(stderr, " Supported options:\n");
	fprintf(stderr, "\t-c config-file\tSpecify the configuration file\n");
	fprintf(stderr, "\t-z zone\t\tThe zone\n");
	fprintf(stderr, "\t-v\t\tPrint version information\n");
	fprintf(stderr, "\t-h\t\tPrint this help information\n\n");
	fprintf(stderr, "Report bugs to <nsd-bugs@nlnetlabs.nl>\n");
	exit(EXIT_FAILURE);
}

static void
version(void)
{
        fprintf(stderr, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        fprintf(stderr, "Written by NLnet Labs.\n\n");
        fprintf(stderr,
                "Copyright (C) 2001-2005 NLnet Labs.  This is free software.\n"
                "There is NO warranty; not even for MERCHANTABILITY or FITNESS\n"
                "FOR A PARTICULAR PURPOSE.\n");
        exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int c;
	int i, j;

	/* LDNS types */
	ldns_pkt *notify;
	ldns_rr *question;
	ldns_rdf *helper;
	ldns_resolver *res;
	ldns_rdf *ldns_zone_name;
	ldns_rdf *ns_addr;

	/* NSD types */
	nsd_options_type *options = NULL;
	nsd_options_zone_type *zone_info = NULL;
	nsd_options_address_type *address= NULL;
	const char *options_file = NULL;
	region_type *region = region_create(xalloc, free);
	const dname_type *zone_name = NULL;
	
	log_init("nsd-notify");

        while ((c = getopt(argc, argv, "c:vhz:")) != -1) {
                switch (c) {
                case 'c':
                        options_file = optarg;
                        break;
                case 'z':
                        zone_name = dname_parse(region, optarg);
                        if (!zone_name) {
                                log_msg(LOG_ERR,
                                        "incorrect domain name '%s'",
                                        optarg);
                                exit(EXIT_FAILURE);
                        }
			ldns_zone_name = dname2ldns_dname_clone(zone_name);
			if (!ldns_zone_name) {
				exit(EXIT_FAILURE);
			}
                        break;
		case 'v':
			version();
                case 'h':
                case '?':
                default:
                        usage();
                }
        }
        argc -= optind;
        argv += optind;

        if (argc != 0) {  /* || zone_name == NULL) { */
                usage();
        }

        options = nsd_load_config(region, options_file);
        if (!options) {
                error(EXIT_FAILURE, "failed to load configuration file '%s'",
                      options_file);
        }

	zone_info = nsd_options_find_zone(options, zone_name);
	if (!zone_info) {
		error(EXIT_FAILURE,
				"zone '%s' not found in the configuration file",
				dname_to_string(zone_name, NULL));
	}

	notify = ldns_pkt_new();
	question = ldns_rr_new();
	res = ldns_resolver_new();

	if (!notify || !question || !res) {
		/* bail out */
		error(EXIT_FAILURE, "cannot create ldns types");
	}

	/* create the rr for inside the pkt */
	ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
	ldns_rr_set_owner(question, ldns_zone_name);
	ldns_rr_set_type(question, LDNS_RR_TYPE_SOA);
	ldns_pkt_set_opcode(notify, LDNS_PACKET_NOTIFY);
	ldns_pkt_push_rr(notify, LDNS_PACKET_QUESTION, question);
	ldns_pkt_set_aa(notify, true);
	ldns_pkt_set_id(notify, 42); /* from original nsd-notify... */

	/* walk all the servers */
	for (i = 0; i < zone_info->notify_count; ++i) {
		for (j = 0; j < zone_info->notify[i]->addresses->count; j++) {
			address = zone_info->notify[i]->addresses->addresses[j];

			/* set the port */
			address->port ? 
				ldns_resolver_set_port(res, 
						(uint16_t)atoi(address->port)):
				ldns_resolver_set_port(res, LDNS_PORT);

			ns_addr = options_address_type2rdf_clone(address);
			if (!ns_addr) {
				 fprintf(stderr, "skipping bad address %s\n", address->address);
				 continue;
			}
			ldns_resolver_push_nameserver(res, ns_addr);

			ldns_pkt_print(stdout, notify);

			if (ldns_resolver_send_pkt(NULL, res, notify) != LDNS_STATUS_OK) {
				fprintf(stderr, "send to %s failed\n", *argv);
			}
			(void)ldns_resolver_pop_nameserver(res); /* remove the nameserver */
		}
	}
        return EXIT_SUCCESS;
}