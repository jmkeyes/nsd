/*
 * nsec3.h -- nsec3 handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef NSEC3_H
#define NSEC3_H

#include <config.h>
#ifdef NSEC3

struct domain;
struct dname;
struct region;
struct zone;
struct namedb;
struct query;
struct answer;
struct rr;
struct nsec3_domain;

/* 
 * Create the hashed name of the nsec3 record
 * for the given dname. 
 */
const struct dname *nsec3_hash_dname(struct region *region, 
	struct zone *zone, const struct dname *dname);

/*
 *
 */

int
find_zone_nsec3(struct namedb *namedb,
		struct zone *zone,
		struct rr **pp_rr);

int
prehash_zone_incremental(struct namedb *db,
			 struct zone *zone);

int
prehash_zone(struct namedb *db,
	     struct zone *zone);

/* 
 * calculate prehash information for all zones,
 * selects only updated=1 zones if bool set.
 */
int
prehash(struct namedb* db,
	int updated_only);

/* 
 * finds nsec3 that covers the given domain dname. 
 * returns true if the find is exact. 
 * hashname is the already hashed dname for the NSEC3.
 */
#if 0
int nsec3_find_cover(struct namedb *db,
		     struct zone *zone, 
		     struct dname const *hashname,
		     struct nsec3_domain **pp_nsec3_domain);
#endif

/*
 * _answer_ Routines used to add the correct nsec3 record to a query answer.
 * cnames etc may have been followed, hence original name.
 */
/* 
 * add proof for wildcards that the name below the wildcard.parent
 * does not exist 
 */
extern int
nsec3_answer_wildcard(struct query *query,
		      struct answer *answer,
		      struct domain *wildcard,
		      struct namedb* db,
		      const struct dname *qname);

/* 
 * add NSEC3 to provide domain name but not rrset exists,
 * this could be a query for a DS or NSEC3 type
 */
extern int
nsec3_answer_nodata(struct query *query,
		    struct answer *answer, 
		    struct domain *original);

/* 
 * add NSEC3 for a delegation (optout stuff)
 */
extern int
nsec3_answer_delegation(struct query *query,
			struct answer *answer);

/* 
 * add NSEC3 for authoritative answers.
 * match==0 is an nxdomain. 
 */
extern int
nsec3_answer_authoritative(struct domain** match,
			   struct query *query, 
			   struct answer *answer,
			   struct domain* closest_encloser, 
			   struct namedb* db,
			   const struct dname* qname);

/* 
 * True if domain is a NSEC3 (+RRSIG) data only variety.
 * pass nonNULL zone to filter for particular zone. 
 */
int domain_has_only_NSEC3(struct domain* domain, struct zone* zone);

#endif /* NSEC3 */
#endif /* NSEC3_H*/
