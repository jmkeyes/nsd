%{
/*
 * zlexer.lex - lexical analyzer for (DNS) zone files
 * 
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "zonec.h"
#include "dname.h"
#include "zparser.h"

#if 0
#define LEXOUT(s)  printf s /* used ONLY when debugging */
#else
#define LEXOUT(s)
#endif

static int parsestr(char * yytext, enum rr_spot *in_rr);

static YY_BUFFER_STATE include_stack[MAXINCLUDES];
static zparser_type zparser_stack[MAXINCLUDES];
static int include_stack_ptr = 0;

static void
push_parser_state(FILE *input)
{
	/*
	 * Save file specific variables on the include stack.
	 */
	zparser_stack[include_stack_ptr].filename = parser->filename;
	zparser_stack[include_stack_ptr].line = parser->line;
	zparser_stack[include_stack_ptr].origin = parser->origin;
	include_stack[include_stack_ptr] = YY_CURRENT_BUFFER;
	yy_switch_to_buffer(yy_create_buffer(input, YY_BUF_SIZE));
	++include_stack_ptr;
}

static void
pop_parser_state(void)
{
	--include_stack_ptr;
	parser->filename = zparser_stack[include_stack_ptr].filename;
	parser->line = zparser_stack[include_stack_ptr].line;
	parser->origin = zparser_stack[include_stack_ptr].origin;
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_switch_to_buffer(include_stack[include_stack_ptr]);
}

%}

SPACE   [ \t]
LETTER  [a-zA-Z]
NEWLINE \n
ZONESTR [a-zA-Z0-9+/=:_!\-\*#%&^\[\]?@]
DOLLAR  \$
COMMENT ;
DOT     \.
SLASH   \\
BIT	[^\]]|\\.
ANY     [^\"]|\\.
Q       \"

%START	incl

%%
    static int paren_open = 0;
    static enum rr_spot in_rr = outside;
{SPACE}*{COMMENT}.*     /* ignore */
^@                      {
		            LEXOUT(("ORIGIN "));		
                            in_rr = expecting_dname;
                            return ORIGIN;
                        }
^{DOLLAR}TTL            return DIR_TTL;
^{DOLLAR}ORIGIN         return DIR_ORIG;
^{DOLLAR}INCLUDE        BEGIN(incl);

			/* see
			 * http://dinosaur.compilertools.net/flex/flex_12.html#SEC12
			 */
<incl>[^\n]+ 		{ 	
				char *tmp;
				domain_type *origin = parser->origin;
				
				if (include_stack_ptr >= MAXINCLUDES ) {
					zc_error("Includes nested too deeply (>%d)",
						 MAXINCLUDES);
					exit(1);
            			}

				/* Remove trailing comment.  */
				tmp = strrchr(yytext, ';');
				if (tmp) {
					*tmp = '\0';
				}
				strip_string(yytext);

				/* Parse origin for include file.  */
				tmp = strrchr(yytext, ' ');
				if (tmp) {
					const dname_type *dname;
					
					/* split the original yytext */
					*tmp = '\0';
					strip_string(yytext);

					dname = dname_parse(parser->region,
							    tmp + 1);
					if (!dname) {
						zc_error("incorrect include origin '%s'",
							 tmp + 1);
					} else {
						origin = domain_table_insert(
							parser->db->domains,
							dname);
					}
				}
				
		        	yyin = fopen(yytext, "r");
        			if (!yyin) {
					zc_error("Cannot open include file '%s'",
						 yytext);
				    	exit(1);
				}

				push_parser_state(yyin);
					
				/* Initialize parser for include file.  */
				parser->filename
					= region_strdup(parser->region, yytext);
				parser->line = 1;
				parser->origin = origin;

			        BEGIN(INITIAL);
        		}	
<<EOF>>			{
				if (include_stack_ptr == 0) {
					yyterminate();
        			} else {
					pop_parser_state();
            			}
        		}
^{DOLLAR}{LETTER}+      { zc_warning("Unknown $directive: %s", yytext); }
^{DOT}                  {
                            /* a ^. means the root zone... also set in_rr */
                            in_rr = expecting_dname;
			    LEXOUT((". "));
                            return '.';
                        }
{DOT}                   { LEXOUT((". ")); return '.'; }
{SLASH}#                { LEXOUT(("\\# "));return URR; }
^{SPACE}+               {
                            if ( paren_open == 0 ) { 
                                in_rr = after_dname;
                                return PREV;
                            }
                        }
{NEWLINE}               {
                            parser->line++;
                            if ( paren_open == 0 ) { 
                                in_rr = outside;
				LEXOUT(("NL \n"));
                                return NL;
                            } else {
				    LEXOUT(("SP "));
				    return SP;
			    }
                        }
{SPACE}*\({SPACE}*      {
                            if ( paren_open == 1 ) {
				zc_error("Nested parentheses");
                                yyterminate();
                            }
                            LEXOUT(("SP( "));
                            paren_open = 1;
                            return SP;
                        }
{SPACE}*\){SPACE}*      {
                            if ( paren_open == 0 ) {
				zc_error("Unterminated parentheses");
                                yyterminate();
                            }
                            LEXOUT(("SP) "));
                            paren_open = 0;
                            return SP;
                        }
{SPACE}+                {
                            if ( paren_open == 0 ) {
                                if (in_rr == expecting_dname)
                                    in_rr = after_dname;
                            }
                            LEXOUT(("SP "));
                            return SP;
                        }
\\\[{BIT}*\]	{
			/* bitlabels */
			yytext[strlen(yytext) - 1] = '\0';
			yylval.data.len = strlen(yytext + 2);
			yylval.data.str = region_strdup(parser->rr_region, yytext + 2);
			if (in_rr == expecting_dname || in_rr == outside) 
				in_rr = after_dname;
			return BITLAB;
		}

{Q}({ANY})*{Q}   {
                            /* this matches quoted strings */
			    /* Strip leading and ending quotes.  */
			    yytext[strlen(yytext) - 1] = '\0';
                            return parsestr(yytext + 1, &in_rr);
                        }
({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word */
			    return parsestr(yytext, &in_rr);
                        }
.                       {
                            /* we should NEVER reach this
                             * bail out with an error */
			    zc_error("Unknown character seen - is this a zonefile?");
                            /*exit(1); [XXX] we should exit... */
                        }
%%

/*
 * Analyze "word" to see if it matches an RR type, possibly by using
 * the "TYPExxx" notation.  If it matches, the corresponding token is
 * returned and the TYPE parameter is set to the RR type value.
 */
static int
zrrtype (const char *word, uint16_t *type) 
{
	uint16_t t = lookup_type_by_name(word);
	if (t != 0) {
		rrtype_descriptor_type *entry = rrtype_descriptor_by_type(t);
		*type = t;
		return entry->token;
	}

	return 0;
}


/*
 * Remove \DDD constructs from the input. See RFC 1035, section 5.1.
 */
static size_t
zoctet(char *text) 
{
	/*
	 * s follows the string, p lags behind and rebuilds the new
	 * string
	 */
	char *s;
	char *p;
	
	for (s = p = text; *s; ++s, ++p) {
		assert(p <= s);
		if (s[0] != '\\') {
			/* Ordinary character.  */
			*p = *s;
		} else if (isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3])) {
			/* \DDD escape.  */
			int val = (digittoint(s[1]) * 100 +
				   digittoint(s[2]) * 10 +
				   digittoint(s[3]));
			if (0 <= val && val <= 255) {
				s += 3;
				*p = val;
			} else {
				zc_warning("text escape \\DDD overflow");
				*p = *++s;
			}
		} else if (s[1] != '\0') {
			/* \X where X is any character, keep X.  */
			*p = *++s;
		} else {
			/* Trailing backslash, ignore it.  */
			zc_warning("trailing backslash ignored");
			--p;
		}
	}
	return p - text;
}

static int
parsestr(char *yytext, enum rr_spot *in_rr)
{
	int token;
	const char *t; char *ztext;

	switch(*in_rr) {
	case after_dname:
		/* type */
		token = zrrtype(yytext, &yylval.type);
		if (token != 0) {
			*in_rr = reading_type;
			return token;
		}

		/* class */
		if (strcasecmp(yytext, "IN") == 0 ||
		    strcasecmp(yytext,"CLASS1") == 0 ) {
			yylval.klass = CLASS_IN;
			LEXOUT(("IN "));
			return T_IN;
		} else if (strcasecmp(yytext, "CH") == 0) {
			yylval.klass = CLASS_CHAOS;
			return T_CH;
		} else if (strcasecmp(yytext, "HS") == 0) {
			yylval.klass = CLASS_HS;
			return T_HS;
		}

		/* ttl */
		strtottl(yytext, &t);
		if ( *t == 0 ) {
			/* was parseable */
			yylval.data.str = yytext;
			yylval.data.len = strlen(yytext); /*needed?*/
			LEXOUT(("TTL "));
			return TTL;
		}
		/* Fall through, default first, order matters.  */
	default:
		/*
		 * Check to see if someone used @ in the rdata if so
		 * return the origin str, and RD_ORIGIN token.
		 */
		if (strcasecmp(yytext, "@") == 0) {
			ztext = (char *)dname_to_string(
				domain_dname(parser->origin), NULL);
			yylval.data.len = strlen(ztext);
			yylval.data.str = ztext;
			LEXOUT(("RDATA_ORI "));
			return RD_ORIGIN;
		}
		ztext = region_strdup(parser->rr_region, yytext);
		yylval.data.len = zoctet(ztext);
		yylval.data.str = ztext;
		LEXOUT(("STR "));
		return STR;
	case outside:
		/* should match ^ */
		ztext = region_strdup(parser->rr_region, yytext);
		yylval.data.len = zoctet(ztext);
		yylval.data.str = ztext;
		*in_rr = expecting_dname;
		LEXOUT(("STR "));
		return STR;
	}
}
