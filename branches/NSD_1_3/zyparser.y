%{
/*
 * $Id: zyparser.y,v 1.37.2.2 2003/10/06 13:19:21 miekg Exp $
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
#include "zonec2.h"
#include "zparser2.h"

/* these need to be global, otherwise they cannot be used inside yacc */
struct zdefault_t * zdefault;
struct RR * current_rr;

/* [XXX] should be local? */
int progress = 10000;

%}
/* this list must be in exactly the same order as *RRtypes[] in zlparser.lex. 
 * The only changed are:
 * - NSAP-PRT is named NSAP_PTR
 * - NULL which is named YYNULL.
 */
/* RR types */
%token A NS MX TXT CNAME AAAA PTR NXT KEY SOA SIG SRV CERT LOC MD MF MB
%token MG MR YYNULL WKS HINFO MINFO RP AFSDB X25 ISDN RT NSAP NSAP_PTR PX GPOS 
%token EID NIMLOC ATMA NAPTR KX A6 DNAME SINK OPT APL UINFO UID GID 
%token UNSPEC TKEY TSIG IXFR AXFR MAILB MAILA

/* other tokens */
%token ORIGIN NL SP STR DIR_TTL DIR_ORIG PREV IN CH HS

/* unknown RRs */
%token UN_RR UN_CLASS UN_TYPE

%%
lines:  /* empty line */
    |   lines line
    { if ( zdefault->line % progress == 0 )
        printf("\nzonec: reading zone \"%s\": %lu\n", zdefault->filename,
	       (unsigned long) zdefault->line);
    }
    |    error      { yyerrok; }
    ;

line:   NL
    |   DIR_TTL dir_ttl
    |   DIR_ORIG dir_orig
    |   rr
    {   /* rr should be fully parsed */
        /*zprintrr(stderr, current_rr); DEBUG */
        current_rr->rdata = xrealloc(current_rr->rdata, sizeof(void *) * (zdefault->_rc + 1));

	    process_rr(current_rr);
	    current_rr->rdata = xalloc(sizeof(void *) * (MAXRDATALEN + 1));
	    zdefault->_rc = 0;
    }
    ;

/* a string of whitespaces usefull when people use ( in files */
sp:		SP
	|	sp SP
	;

trail:	NL	
	|	sp NL
	;

dir_ttl:    SP STR trail
    { 
        if ($2.len > MAXDOMAINLEN ) {
            yyerror("$TTL value is too large");
            return 1;
        } 
        /* perform TTL conversion */
        if ( ( zdefault->ttl = zparser_ttl2int($2.str)) == -1 )
            zdefault->ttl = DEFAULT_TTL;

        free($2.str);
    }
    ;

dir_orig:   sp dname trail
    {
        /* [xxx] does $origin not effect previous */
        if ( $2.len > MAXDOMAINLEN ) { 
            yyerror("$ORIGIN domain name is too large");
            return 1;
        } 
	free(zdefault->origin); /* old one can go */
        zdefault->origin = (uint8_t *)dnamedup($2.str);
        zdefault->origin_len = $2.len;
        free($2.str);
    }
    ;

rr:     ORIGIN sp rrrest trail
    {
        /* starts with @, use the origin */
        current_rr->dname = zdefault->origin;

        /* also set this as the prev_dname */
        zdefault->prev_dname = zdefault->origin;
        zdefault->prev_dname_len = zdefault->origin_len; /* what about this len? */
        free($1.str);
    }
    |   PREV rrrest trail
    {
        /* a tab, use previously defined dname */
        /* [XXX] is null -> error, not checked (yet) MG */
        current_rr->dname = zdefault->prev_dname;
        
    }
    |   dname sp rrrest trail
    {
        current_rr->dname = $1.str;

        /* set this as previous */
        zdefault->prev_dname = $1.str;
        zdefault->prev_dname_len = $1.len;
    }
    ;

ttl:    STR
    {
        /* set the ttl */
        if ( (current_rr->ttl = zparser_ttl2int($1.str) ) == -1 )
            current_rr->ttl = DEFAULT_TTL;
        free($1.str);
    }
    ;

in:     IN
    {
        /* set the class */
        current_rr->class =  zdefault->class;
    }
    |   UN_CLASS
    {
	    /* unknown RR seen */
	    current_rr->class = intbyclassxx($1.str);
	    if ( current_rr->class == 0 ) {
		    fprintf(stderr,"CLASSXXX parse error, setting to IN class.\n");
		    current_rr->class = zdefault->class;
	    }
    }
    ;

rrrest: classttl rtype 
    {
        /* terminate the rdata list - NULL does not have rdata */
        zadd_rdata_finalize(zdefault);
    }
    ;

classttl:   /* empty - fill in the default, def. ttl and IN class */
    {
        current_rr->ttl = zdefault->ttl;
        current_rr->class = zdefault->class;
    }
    |   in sp         /* no ttl */
    {
        current_rr->ttl = zdefault->ttl;
    }
    |   ttl sp in sp  /* the lot */
    |   in sp ttl sp  /* the lot - reversed */
    |   ttl sp        /* no class */
    {   
        current_rr->class = zdefault->class;
    }
    |   CH sp         { yyerror("CHAOS class not supported"); }
    |   HS sp         { yyerror("HESIOD Class not supported"); }
    |   ttl sp CH sp         { yyerror("CHAOS class not supported"); }
    |   ttl sp HS sp         { yyerror("HESIOD class not supported"); }
    |   CH sp ttl sp         { yyerror("CHAOS class not supported"); }
    |   HS sp ttl sp         { yyerror("HESIOD class not supported"); }
    ;

dname:  abs_dname
    {
        $$.str = $1.str;
        $$.len = $1.len;  /* length really not important anymore */
    }
    |   rel_dname
    {
        /* append origin */
        $$.str = (uint8_t *)cat_dname($1.str, zdefault->origin);
        free($1.str);
        $$.len = $1.len;
    }
    ;

abs_dname:  '.'
    {
            $$.str = (uint8_t *)dnamedup(ROOT);
            $$.len = 1;
    }
    |       rel_dname '.'
    {
            $$.str = cat_dname($1.str, ROOT);
            free($1.str);
            $$.len = $1.len;
    }
    ;

rel_dname:  STR
    {
        $$.str = create_dname($1.str, $1.len);
        $$.len = $1.len + 2; /* total length, label + len byte */
        free($1.str);
    }
    |       rel_dname '.' STR
    {  
        $$.str = cat_dname($1.str, create_dname($3.str,
						  $3.len));
        $$.len = $1.len + $3.len + 1;
        free($1.str);free($3.str);
    }
    ;

/* hex and rdata_txt are equal and are put in the same place in
 * in the zone file
 */
hex:	STR 
    {
	$$.str = $1.str;
	$$.len = $1.len;
    }
    |	sp hex sp STR
    ;


/* define what we can parse */

rtype:  SOA sp rdata_soa
    {   
        zadd_rtype("soa");
    }
    |   A sp rdata_a
    {
        zadd_rtype("a");
    }
    |   NS sp rdata_dname
    {
        zadd_rtype("ns");
    }
    |   CNAME sp rdata_dname
    {
        zadd_rtype("cname");
    }
    |   PTR sp rdata_dname
    {   
        zadd_rtype("ptr");
    }
    |   MX sp rdata_mx
    {
        zadd_rtype("mx");
    }
    |   AAAA sp rdata_aaaa
    {
        zadd_rtype("aaaa");
    }
    |	HINFO sp rdata_hinfo
    {
	zadd_rtype("hinfo");
    }
    |   SRV sp rdata_srv
    {
	zadd_rtype("srv");
    }
    /*
    |	UN_TYPE sp UN_RR rdata_unknown
    {
	current_rr->type = intbytypexx($1.str);
	if ( current_rr->type == 0 ) {
	    fprintf(stderr,"TYPEXXX parse error, setting to A.\n");
	    current_rr->type = TYPE_A;
	}
    }
    */
    |	error NL
    {	
	    fprintf(stderr,"Unimplemented RR seen\n");
    }
    ;


/* 
 * below are all the definition for all the different rdata 
 */

rdata_unknown: sp STR sp hex
    {
	/* check_hexlen($1.str, $2.str); */
	zadd_rdata2( zdefault, zparser_conv_hex($4.str) );
	free($4.str);
    }
    ;

rdata_soa:  dname sp dname sp STR sp STR sp STR sp STR sp STR
    {
        /* convert the soa data */
        zadd_rdata2( zdefault, zparser_conv_dname($1.str) );   /* prim. ns */
        zadd_rdata2( zdefault, zparser_conv_dname($3.str) );   /* email */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($5.str) ); /* serial */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($7.str) ); /* refresh */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($9.str) ); /* retry */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($11.str) ); /* expire */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($13.str) ); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (zdefault->minimum = zparser_ttl2int($11.str) ) == -1 )
            zdefault->minimum = DEFAULT_TTL;
        free($1.str);free($3.str);free($5.str);free($7.str);
        free($9.str);free($11.str);free($13.str);
    }
    ;

rdata_dname:   dname
    {
        /* convert a single dname record */
        zadd_rdata2( zdefault, zparser_conv_dname($1.str) ); /* domain name */
        free($1.str);
    }
    ;

rdata_a:    STR '.' STR '.' STR '.' STR
    {
        /* setup the string suitable for parsing */
	    char *ipv4 = xalloc($1.len + $3.len + $5.len + $7.len + 4);
        memcpy(ipv4, $1.str, $1.len);
        memcpy(ipv4 + $1.len , ".", 1);

        memcpy(ipv4 + $1.len + 1 , $3.str, $3.len);
        memcpy(ipv4 + $1.len + $3.len + 1, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + 2 , $5.str, $5.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + 2, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + $5.len + 3 , $7.str, $7.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + $7.len + 3, "\0", 1);

        zadd_rdata2(zdefault, zparser_conv_a(ipv4));
        free($1.str);free($3.str);free($5.str);free($7.str);
        free(ipv4);
    }
    ;


rdata_mx:   STR sp dname
    {
        zadd_rdata2( zdefault, zparser_conv_short($1.str) );  /* priority */
        zadd_rdata2( zdefault, zparser_conv_dname($3.str) );  /* MX host */
        free($1.str);free($3.str);
    }
    ;

rdata_aaaa: STR
    {
        zadd_rdata2( zdefault, zparser_conv_a6($1.str) );  /* IPv6 address */
        free($1.str);
    }
    ;

rdata_hinfo:	STR sp STR
	{
        	zadd_rdata2( zdefault, zparser_conv_text($1.str) ); /* CPU */
        	zadd_rdata2( zdefault, zparser_conv_text($3.str) );  /* OS*/
        	free($1.str);free($3.str);
	}
	;

rdata_srv:	STR sp STR sp STR sp dname
	{
		zadd_rdata2( zdefault, zparser_conv_short($1.str) ); /* prio */
		zadd_rdata2( zdefault, zparser_conv_short($3.str) ); /* weight */
		zadd_rdata2( zdefault, zparser_conv_short($5.str) ); /* port */
		zadd_rdata2( zdefault, zparser_conv_dname($7.str) ); /* target name */
		free($1.str);free($3.str);free($5.str);free($7.str);
	}
	;
%%

int
yywrap()
{
    return 1;
}

/* print an error. S has the message. zdefault is global so just access it */
int
yyerror(const char *s)
{
    fprintf(stderr,"error: %s in %s, line %lu\n",s, zdefault->filename,
    (unsigned long) zdefault->line);
    zdefault->errors++;
    if ( zdefault->errors++ > 10 ) {
        fprintf(stderr,"too many errors (50+)\n");
        exit(1);
    }
    return 0;
}