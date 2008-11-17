/*
 * dns.h -- DNS definitions.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _DNS_H_
#define _DNS_H_

enum rr_section {
	QUESTION_SECTION,
	ANSWER_SECTION,
	AUTHORITY_SECTION,
	ADDITIONAL_SECTION,
	/*
	 * Use a split additional section to ensure A records appear
	 * before any AAAA records (this is recommended practice to
	 * avoid truncating the additional section for IPv4 clients
	 * that do not specify EDNS0), and AAAA records before other
	 * types of additional records (such as X25 and ISDN).
	 * Encode_answer sets the ARCOUNT field of the response packet
	 * correctly.
	 */
	ADDITIONAL_A_SECTION = ADDITIONAL_SECTION,
	ADDITIONAL_AAAA_SECTION,
	ADDITIONAL_OTHER_SECTION,

	RR_SECTION_COUNT
};
typedef enum rr_section rr_section_type;

/* Possible OPCODE values */
#define OPCODE_QUERY		0 	/* a standard query (QUERY) */
#define OPCODE_IQUERY		1 	/* an inverse query (IQUERY) */
#define OPCODE_STATUS		2 	/* a server status request (STATUS) */
#define OPCODE_NOTIFY		4 	/* NOTIFY */
#define OPCODE_UPDATE		5 	/* Dynamic update */

/* Possible RCODE values */
#define RCODE_OK		0 	/* No error condition */
#define RCODE_FORMAT		1 	/* Format error */
#define RCODE_SERVFAIL		2 	/* Server failure */
#define RCODE_NXDOMAIN		3 	/* Name Error */
#define RCODE_IMPL		4 	/* Not implemented */
#define RCODE_REFUSE		5 	/* Refused */
#define RCODE_NOTAUTH		9	/* Not authorized */

/* Standardized NSD return code.  Partially maps to DNS RCODE values.  */
enum nsd_rc
{
	/* Discard the client request.  */
	NSD_RC_DISCARD  = -1,
	/* OK, continue normal processing.  */
	NSD_RC_OK       = RCODE_OK,
	/* Return the appropriate error code to the client.  */
	NSD_RC_FORMAT   = RCODE_FORMAT,
	NSD_RC_SERVFAIL = RCODE_SERVFAIL,
	NSD_RC_NXDOMAIN = RCODE_NXDOMAIN,
	NSD_RC_IMPL     = RCODE_IMPL,
	NSD_RC_REFUSE   = RCODE_REFUSE,
	NSD_RC_NOTAUTH  = RCODE_NOTAUTH
};
typedef enum nsd_rc nsd_rc_type;

/* RFC1035 */
#define CLASS_IN	1	/* Class IN */
#define CLASS_CS	2	/* Class CS */
#define CLASS_CH	3	/* Class CHAOS */
#define CLASS_HS	4	/* Class HS */
#define CLASS_ANY	255	/* Class ANY */

#define TYPE_A		1	/* a host address */
#define TYPE_NS		2	/* an authoritative name server */
#define TYPE_MD		3	/* a mail destination (Obsolete - use MX) */
#define TYPE_MF		4	/* a mail forwarder (Obsolete - use MX) */
#define TYPE_CNAME	5	/* the canonical name for an alias */
#define TYPE_SOA	6	/* marks the start of a zone of authority */
#define TYPE_MB		7	/* a mailbox domain name (EXPERIMENTAL) */
#define TYPE_MG		8	/* a mail group member (EXPERIMENTAL) */
#define TYPE_MR		9	/* a mail rename domain name (EXPERIMENTAL) */
#define TYPE_NULL	10	/* a null RR (EXPERIMENTAL) */
#define TYPE_WKS	11	/* a well known service description */
#define TYPE_PTR	12	/* a domain name pointer */
#define TYPE_HINFO	13	/* host information */
#define TYPE_MINFO	14	/* mailbox or mail list information */
#define TYPE_MX		15	/* mail exchange */
#define TYPE_TXT	16	/* text strings */
#define TYPE_RP		17	/* RFC1183 */
#define TYPE_AFSDB	18	/* RFC1183 */
#define TYPE_X25	19	/* RFC1183 */
#define TYPE_ISDN	20	/* RFC1183 */
#define TYPE_RT		21	/* RFC1183 */
#define TYPE_NSAP	22	/* RFC1706 */

#define TYPE_SIG	24	/* 2535typecode */
#define TYPE_KEY	25	/* 2535typecode */
#define TYPE_PX		26	/* RFC2163 */

#define TYPE_AAAA	28	/* ipv6 address */
#define TYPE_LOC	29	/* LOC record  RFC1876 */
#define TYPE_NXT	30	/* 2535typecode */

#define TYPE_SRV	33	/* SRV record RFC2782 */

#define TYPE_NAPTR	35	/* RFC2915 */
#define TYPE_KX		36	/* RFC2230 */
#define TYPE_CERT	37	/* RFC2538 */

#define TYPE_DNAME	39	/* RFC2672 */

#define TYPE_OPT	41	/* Pseudo OPT record... */
#define TYPE_APL	42	/* RFC3123 */
#define TYPE_DS		43	/* draft-ietf-dnsext-delegation */
#define TYPE_SSHFP	44	/* SSH Key Fingerprint */

#define TYPE_RRSIG	46	/* draft-ietf-dnsext-dnssec-25 */
#define TYPE_NSEC	47
#define TYPE_DNSKEY	48

#define TYPE_TSIG	250
#define TYPE_IXFR	251
#define TYPE_AXFR	252
#define TYPE_MAILB	253	/* A request for mailbox-related records (MB, MG or MR) */
#define TYPE_MAILA	254	/* A request for mail agent RRs (Obsolete - see MX) */
#define TYPE_ANY	255	/* any type (wildcard) */

#define MAXLABELLEN	63
#define MAXDOMAINLEN	255

#define MAXRDATALEN	64 /* This is more than enough, think multiple TXT.  */
#define MAX_RDLENGTH	65535

/* Maximum size of a single RR.  */
#define MAX_RR_SIZE \
	(MAXDOMAINLEN + sizeof(uint32_t) + 4*sizeof(uint16_t) + MAX_RDLENGTH)

#define IP4ADDRLEN	(32/8)
#define IP6ADDRLEN	(128/8)

/*
 * The different types of RDATA that can appear in the zone file.
 */
enum rdata_kind
{
	RDATA_KIND_DNAME,	/* Domain name.  */
	RDATA_KIND_TEXT,	/* Text string.  */
	RDATA_KIND_BYTE,	/* 8-bit integer.  */
	RDATA_KIND_SHORT,	/* 16-bit integer.  */
	RDATA_KIND_LONG,	/* 32-bit integer.  */
	RDATA_KIND_A,		/* 32-bit IPv4 address.  */
	RDATA_KIND_AAAA,	/* 128-bit IPv6 address.  */
	RDATA_KIND_RRTYPE,	/* RR type.  */
	RDATA_KIND_ALGORITHM,	/* Cryptographic algorithm.  */
	RDATA_KIND_CERTIFICATE_TYPE,
	RDATA_KIND_PERIOD,	/* Time period (32-bits).  */
	RDATA_KIND_TIME,	/* Time (32-bits).  */
	RDATA_KIND_BASE64,	/* Base-64 binary data.  */
	RDATA_KIND_HEX,		/* Hexadecimal binary data.  */
	RDATA_KIND_NSAP,	/* NSAP.  */
	RDATA_KIND_APL,		/* APL.  */
	RDATA_KIND_SERVICES,	/* Protocol and port number bitmap.  */
	RDATA_KIND_NXT,		/* NXT type bitmap.  */
	RDATA_KIND_NSEC,	/* NSEC type bitmap.  */
	RDATA_KIND_LOC,		/* Location data.  */
	RDATA_KIND_UNKNOWN	/* Unknown data.  */
};
typedef enum rdata_kind rdata_kind_type;

struct rrtype_descriptor
{
	uint16_t    type;	/* RR type */
	const char *name;	/* Textual name.  */
	int         token;	/* Parser token.  */
	int         allow_compression; /* Allow dname compression.  */
	uint8_t     minimum;	/* Minimum number of RDATAs.  */
	uint8_t     maximum;	/* Maximum number of RDATAs.  */
	uint8_t     rdata_kinds[MAXRDATALEN]; /* rdata_kind_type  */
};
typedef struct rrtype_descriptor rrtype_descriptor_type;

/*
 * Indexed by type.  The special type "0" can be used to get a
 * descriptor for unknown types (with one binary rdata).
 */
#define RRTYPE_DESCRIPTORS_LENGTH  (TYPE_DNSKEY+1)
extern rrtype_descriptor_type rrtype_descriptors[RRTYPE_DESCRIPTORS_LENGTH];

static inline rrtype_descriptor_type *
rrtype_descriptor_by_type(uint16_t type)
{
	return (type < RRTYPE_DESCRIPTORS_LENGTH
		? &rrtype_descriptors[type]
		: &rrtype_descriptors[0]);
}

rrtype_descriptor_type *rrtype_descriptor_by_name(const char *name);

const char *rrtype_to_string(uint16_t rrtype);

/*
 * Lookup the type in the ztypes lookup table.  If not found, check if
 * the type uses the "TYPExxx" notation for unknown types.
 *
 * Return 0 if no type matches.
 */
uint16_t rrtype_from_string(const char *name);

const char *rrclass_to_string(uint16_t rrclass);
uint16_t rrclass_from_string(const char *name);

#ifdef __cplusplus
inline rr_section_type
operator++(rr_section_type &lhs)
{
	lhs = (rr_section_type) ((int) lhs + 1);
	return lhs;
}
#endif /* __cplusplus */

#endif /* _DNS_H_ */