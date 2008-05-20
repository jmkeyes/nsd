%{
/*
 * $Id: zparser.y,v 1.8 2003/11/05 15:21:54 erik Exp $
 *
 * zyparser.y -- yacc grammar for (DNS) zone files
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license
 */

#include <config.h>
	
#include <stdio.h>
#include <string.h>

#include "dname.h"
#include "namedb.h"
#include "zonec.h"

/* these need to be global, otherwise they cannot be used inside yacc */
zparser_type *current_parser;
rr_type *current_rr;

int yywrap(void);

rdata_atom_type temporary_rdata[MAXRDATALEN + 1];
/* this hold the nxt bits */
uint8_t nxtbits[16] = { '\0','\0','\0','\0',
	 		'\0','\0','\0','\0',
			'\0','\0','\0','\0',
			'\0','\0','\0','\0' };
%}
/* this list must be in exactly the same order as *RRtypes[] in zlparser.lex. 
 * The only changed are:
 * - NSAP-PRT is named NSAP_PTR
 * - NULL which is named YYNULL.
 */
/* RR types */

%union {
	domain_type      *domain;
	const dname_type *dname;
	struct lex_data   data;
	uint32_t          ttl;
	uint16_t          class;
	uint16_t          type;
}

%token <type> A NS MX TXT CNAME AAAA PTR NXT KEY SOA SIG SRV CERT LOC MD MF MB
%token <type> MG MR YYNULL WKS HINFO MINFO RP AFSDB X25 ISDN RT NSAP NSAP_PTR PX GPOS 
%token <type> EID NIMLOC ATMA NAPTR KX A6 DNAME SINK OPT APL UINFO UID GID 
%token <type> UNSPEC TKEY TSIG IXFR AXFR MAILB MAILA DS RRSIG NSEC DNSKEY

/* other tokens */
%token         DIR_TTL DIR_ORIG NL ORIGIN SP
%token <data>  STR PREV
%token <class> IN CH HS

/* unknown RRs */
%token         UN_RR
%token <class> UN_CLASS
%token <type>  UN_TYPE

%type <domain> dname abs_dname
%type <dname>  rel_dname
%type <data>   str_seq hex_seq nxt_seq

%%
lines:  /* empty line */
    |   lines line
    |   error      { error("syntax error"); yyerrok; }
    ;

line:   NL
    |   DIR_TTL dir_ttl
    |   DIR_ORIG dir_orig
    |   rr
    {   /* rr should be fully parsed */
        /*zprintrr(stderr, current_rr); DEBUG */
	    current_rr->zone = current_parser->current_zone;
	    current_rr->rdata = region_alloc_init(
		    zone_region,
		    current_rr->rdata,
		    sizeof(rdata_atom_type) * (current_parser->_rc + 1));

	    process_rr(current_parser, current_rr);

	    region_free_all(rr_region);
	    
	    current_rr->rdata = temporary_rdata;
	    current_parser->_rc = 0;
    }
    ;

/* needed to cope with ( and ) in arbitary places */
sp:		SP
  	|	sp SP
	;

trail:		NL
	|	sp NL
	;

dir_ttl:    SP STR trail
    { 
        if ($2.len > MAXDOMAINLEN ) {
            error("$TTL value is too large");
            return 1;
        } 
        /* perform TTL conversion */
        if ( ( current_parser->ttl = zparser_ttl2int($2.str)) == -1 )
            current_parser->ttl = DEFAULT_TTL;
    }
    ;

dir_orig:   SP abs_dname trail
    {
        /* [xxx] does $origin not effect previous */
	/* [XXX] label length checks should be in dname functions */
        if ( $2->dname->name_size > MAXDOMAINLEN ) { 
            error("$ORIGIN domain name is too large");
            return 1;
        }

	/* Copy from RR region to zone region.  */
        current_parser->origin = $2;
    }
    ;

rr:     ORIGIN SP rrrest
    {
        current_rr->domain = current_parser->origin;

        current_parser->prev_dname = current_parser->origin;
    }
    |   PREV rrrest
    {
        /* a tab, use previously defined dname */
        /* [XXX] is null -> error, not checked (yet) MG */
        current_rr->domain = current_parser->prev_dname;
        
    }
    |   dname SP rrrest
    {
	    /* Copy from RR region to zone region.  */
	    current_rr->domain = $1;

	    /* set this as previous */
	    current_parser->prev_dname = current_rr->domain;
    }
    ;

ttl:    STR
    {
        /* set the ttl */
        if ( (current_rr->ttl = zparser_ttl2int($1.str) ) == -1 )
            current_rr->ttl = DEFAULT_TTL;
    }
    ;

in:     IN
    {
        /* set the class */
        current_rr->class =  current_parser->class;
    }
    |   UN_CLASS
    {
	    /* unknown RR seen */
	    current_rr->class = $1;
    }
    ;

rrrest: classttl rtype 
    {
        zadd_rdata_finalize(current_parser);
    }
    ;

classttl:   /* empty - fill in the default, def. ttl and IN class */
    {
        current_rr->ttl = current_parser->ttl;
        current_rr->class = current_parser->class;
    }
    |   in SP         /* no ttl */
    {
        current_rr->ttl = current_parser->ttl;
    }
    |   ttl SP in SP  /* the lot */
    |   in SP ttl SP  /* the lot - reversed */
    |   ttl SP        /* no class */
    {   
        current_rr->class = current_parser->class;
    }
    |   CH SP         { error("CHAOS class not supported"); }
    |   HS SP         { error("HESIOD Class not supported"); }
    |   ttl SP CH SP         { error("CHAOS class not supported"); }
    |   ttl SP HS SP         { error("HESIOD class not supported"); }
    |   CH SP ttl SP         { error("CHAOS class not supported"); }
    |   HS SP ttl SP         { error("HESIOD class not supported"); }
    ;

dname:      abs_dname
    	|   rel_dname
    	{
		$$ = domain_table_insert(current_parser->db->domains, 
        		cat_dname(rr_region, $1, current_parser->origin->dname));
    	}
    	;

abs_dname:  '.'
    {
	    $$ = current_parser->db->domains->root;
    }
    |       rel_dname '.'
    {
		$$ = domain_table_insert(current_parser->db->domains, $1);
    }
    ;

rel_dname:  STR
    {
        $$ = create_dname(rr_region, $1.str, $1.len);
    }
    |       rel_dname '.' STR
    {  
        $$ = cat_dname(rr_region, $1,
		       create_dname(rr_region, $3.str, $3.len));
    }
    ;

str_seq:	STR
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $1.str));
    	}
    	|   	str_seq sp STR
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $3.str));
    	}	
    	;

/* used to convert a nxt list of types */
/* XXX goes wrong now */
/* get the type and flip a bit */
nxt_seq:	STR
	{
		int t = intbyname($1.str,ztypes);
		set_bit( nxtbits, t );
		
		/* waar bij houden? */
	}
	|	nxt_seq sp STR
	{
		int t = intbyname($3.str,ztypes);
		set_bit( nxtbits, t );
	}
	;

/* this is also (mis)used for b64 and other str lists */
hex_seq:	STR
	{
		$$ = $1;
	}
	|	hex_seq sp STR
	{
		char *hex = region_alloc(rr_region, $3.len + $1.len + 1);
		memcpy(hex, $1.str, $1.len);
		memcpy(hex + $1.len, $3.str, $3.len);
		/* no +1 here */
		*(hex + $1.len + $3.len ) = '\0';
		$$.str = hex;
		$$.len = $1.len + $3.len;
	}
	;


/* define what we can parse */

rtype:
    /*
     * RFC 1035 RR types.  We don't support NULL, WKS, and types
     * marked obsolete.
     */
      CNAME sp rdata_dname 
    { current_rr->type = $1; }
    | HINFO sp rdata_hinfo 
    { current_rr->type = $1; }
    | MB sp rdata_dname		/* Experimental */
    { current_rr->type = $1; }
    | MD sp rdata_dname		/* Obsolete */
    { error("MD is obsolete"); }
    | MF sp rdata_dname		/* Obsolete */
    { error("MF is obsolete"); }
    | MG sp rdata_dname		/* Experimental */
    { current_rr->type = $1; }
    | MINFO sp rdata_minfo /* Experimental */
    { current_rr->type = $1; }
    | MR sp rdata_dname		/* Experimental */
    { current_rr->type = $1; }
    | MX sp rdata_mx 
    { current_rr->type = $1; }
    | NS sp rdata_dname 
    { current_rr->type = $1; }
    | PTR sp rdata_dname 
    { current_rr->type = $1; }
    | SOA sp rdata_soa 
    { current_rr->type = $1; }
    | TXT sp rdata_txt
    { current_rr->type = $1; }
    | A sp rdata_a 
    { current_rr->type = $1; }
    /* RFC 1886. */
    | AAAA sp rdata_aaaa 
    { current_rr->type = $1; }
    | SRV sp rdata_srv
    { current_rr->type = $1; }
    | DS sp rdata_ds
    { current_rr->type = $1; }
    | KEY sp rdata_key
    { current_rr->type = $1; }
    | NXT sp rdata_nxt
    { current_rr->type = $1; }
    | SIG sp rdata_sig
    { current_rr->type = $1; }
    | error NL
    {	
	    warning("Unimplemented RR seen");
    }
    ;

/* 
 *
 * below are all the definition for all the different rdata 
 *
 */

rdata_minfo:   dname sp dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain(current_parser, $1);
        zadd_rdata_domain(current_parser, $3);
    }
    ;

rdata_soa:  dname sp dname sp STR sp STR sp STR sp STR sp STR trail
    {
        /* convert the soa data */
        zadd_rdata_domain( current_parser, $1);                                     /* prim. ns */
        zadd_rdata_domain( current_parser, $3);                                     /* email */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $5.str) ); /* serial */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $7.str) ); /* refresh */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $9.str) ); /* retry */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $11.str) ); /* expire */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $13.str) ); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (current_parser->minimum = zparser_ttl2int($11.str) ) == -1 )
            current_parser->minimum = DEFAULT_TTL;
    }
    ;

rdata_dname:   dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain(current_parser, $1);
    }
    ;

rdata_a:    STR '.' STR '.' STR '.' STR trail
    {
        /* setup the string suitable for parsing */
	    char *ipv4 = region_alloc(rr_region, $1.len + $3.len + $5.len + $7.len + 4);
        memcpy(ipv4, $1.str, $1.len);
        memcpy(ipv4 + $1.len , ".", 1);

        memcpy(ipv4 + $1.len + 1 , $3.str, $3.len);
        memcpy(ipv4 + $1.len + $3.len + 1, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + 2 , $5.str, $5.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + 2, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + $5.len + 3 , $7.str, $7.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + $7.len + 3, "\0", 1);

        zadd_rdata_wireformat(current_parser, zparser_conv_a(zone_region, ipv4));
    }
    ;

rdata_txt: str_seq trail {}
	;

rdata_mx:   STR sp dname trail
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_short(zone_region, $1.str) );  /* priority */
        	zadd_rdata_domain( current_parser, $3);  /* MX host */
    	}
    	;

rdata_aaaa: STR trail
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_a6(zone_region, $1.str) );  /* IPv6 address */
    	}
    	;

rdata_hinfo:	STR sp STR trail
	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $1.str) ); /* CPU */
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $3.str) ); /* OS*/
	}
	;

rdata_srv:	STR sp STR sp STR sp dname trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* prio */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* weight */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $5.str)); /* port */
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $7)); /* target name */
	}
	;

rdata_ds:	STR sp STR sp STR sp hex_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* keytag */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $5.str)); /* type */
		zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, $7.str)); /* hash */
	}
	;

rdata_key:	STR sp STR sp STR sp hex_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* flags */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* proto */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $5.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_b64(zone_region, $7.str)); /* hash */
	}
	;

rdata_nxt:	dname sp nxt_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $1)); /* nxt name */
		zadd_rdata_wireformat(current_parser,
		zparser_conv_nxt(zone_region, nxtbits)); /* nxt name */
		memset(nxtbits, 0 , 16);
	}
	;

rdata_sig:	STR sp STR sp STR sp STR sp STR sp STR sp STR sp dname sp hex_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_rrtype(zone_region, $1.str)); /* rr covered */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $5.str)); /* # labels */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $7.str)); /* # orig TTL */
		zadd_rdata_wireformat(current_parser, zparser_conv_time(zone_region, $9.str)); /* sig exp */
		zadd_rdata_wireformat(current_parser, zparser_conv_time(zone_region, $11.str)); /* sig inc */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $13.str)); /* key id */
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $15)); /* signer name */
		zadd_rdata_wireformat(current_parser, zparser_conv_b64(zone_region, $17.str)); /* sig data */
	}
	;

%%

int
yywrap(void)
{
    return 1;
}