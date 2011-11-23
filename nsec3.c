/*
 * nsec3.c -- nsec3 handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#ifdef NSEC3
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "nsec3.h"
#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"
#include "answer.h"

#define NSEC3_SHA1_HASH 1 /* same type code as DS hash */

#define  ENOERROR	(0)

/**
 ************************************************************************
 * Check if domain has only NSEC3 RRset, ignoring RRSIG RRsets.
 */

int
domain_has_only_NSEC3(struct domain* domain,
		      struct zone* zone)
{
	rrset_type* rrset = domain->rrsets;
	int nsec3_seen = 0;
	int rrsig_seen = 0;

	while (rrset != NULL) {
		if ((rrset->zone == zone) ||
		    (zone == NULL)) {
			if (rrset->rrs[0].type == TYPE_NSEC3)
				nsec3_seen = 1;
			else if (rrset->rrs[0].type == TYPE_RRSIG)
				rrsig_seen = 1;
			else
				return 0;
		}
		rrset = rrset->next;
	}
	return nsec3_seen;
}

/**
 ************************************************************************
 */

static void
detect_nsec3_params(rr_type *nsec3_apex,
		    unsigned char const **salt,
		    int *salt_len,
		    int *iter)
{
	/* always uses first NSEC3 record with SOA bit set */
	assert(nsec3_apex != NULL);
	assert(salt != NULL);
	assert(salt_len != NULL);
	assert(iter != NULL);

	*salt_len = rdata_atom_data(nsec3_apex->rdatas[3])[0];
	*salt = (unsigned char *) (rdata_atom_data(nsec3_apex->rdatas[3])+1);
	*iter = read_uint16(rdata_atom_data(nsec3_apex->rdatas[2]));
}

/**
 ************************************************************************
 */

static dname_type const *
nsec3_hash_dname_param(region_type *region,
		       zone_type *zone,
		       dname_type const *dname,
		       rr_type *param_rr)
{
        unsigned char hash[SHA_DIGEST_LENGTH];
	char b32[SHA_DIGEST_LENGTH * 2 + 1];

	unsigned char const *nsec3_salt = NULL;

	int nsec3_saltlength = 0;
	int nsec3_iterations = 0;

	dname_type const *hashed_dname;

	detect_nsec3_params(param_rr,
			    &nsec3_salt,
			    &nsec3_saltlength,
			    &nsec3_iterations);

	iterated_hash(hash,
		      nsec3_salt,
		      nsec3_saltlength,
		      dname_name(dname),
		      dname->name_size,
		      nsec3_iterations);

	b32_ntop(hash,
		 sizeof(hash),
		 b32,
		 sizeof(b32));

	hashed_dname = dname_parse(region,
				   b32);
	
	if (hashed_dname != NULL) {
		hashed_dname = dname_concatenate(region,
						 hashed_dname,
						 domain_dname(zone->apex));
	}

	return hashed_dname;
}

/**
 ************************************************************************
 */

dname_type const *
nsec3_hash_dname(region_type *region,
		 zone_type *zone,
		 dname_type const *dname)
{
	return nsec3_hash_dname_param(region,
				      zone,
				      dname,
				      zone->nsec3_soa_rr);
}

/**
 ************************************************************************
 * Determine if the NSEC3 record covers a SOA RRset
 */

static int
nsec3_has_soa(rr_type* rr)
{
	return ((rdata_atom_size(rr->rdatas[5]) >= 3) && /* has types in bitmap */
		(rdata_atom_data(rr->rdatas[5])[0] == 0) && /* first window = 0, */
		/* [1]: windowlen must be >= 1 */
		((rdata_atom_data(rr->rdatas[5])[2] & 0x02) == 0x02)); /* SOA bit set */
}

/**
 ************************************************************************
 */

static int
nsec3_check_param_rrset(struct zone *zone,
			uint32_t rr_num,
			struct rr *param_rr)
{
	uint8_t algorithm;
	uint8_t flags;

	algorithm = rdata_atom_data(param_rr->rdatas[0])[0];
	flags = rdata_atom_data(param_rr->rdatas[1])[0];

	if (algorithm != NSEC3_SHA1_HASH) {
		log_msg(LOG_ERR,
			"%s NSEC3PARAM entry %u: "
			"unknown hash algo %d",
			dname_to_string(domain_dname(zone->apex),
					NULL),
			rr_num,
			algorithm);
		return EINVAL;
	}
	
	if (flags != 0) {
		/* draft-nsec3-09: NSEC3PARAM records with flags
		   field value other than zero MUST be ignored. */
		return EINVAL;
	}

	return ENOERROR;
}

/**
 ************************************************************************
 * Find the NSEC3 RRset belonging to the zone apex which matches the
 * NSEC3 parameters of zone NSEC3PARAM RR[rr_num].
 */

static int
find_zone_nsec3_param_rrset(struct region *region,
			    struct namedb *namedb,
			    struct zone *zone,
			    uint32_t rr_num,
			    struct rr *param_rr,
			    struct rrset **pp_nsec3_rrset)
{
	struct domain *domain;
	dname_type const *hashed_apex;
	struct rrset *nsec3_rrset;

	if (pp_nsec3_rrset == NULL) {
		return EINVAL;
	}

	*pp_nsec3_rrset = NULL;

	/* check hash of apex -> NSEC3 with soa bit on */
	hashed_apex = nsec3_hash_dname_param(region,
					     zone,
					     domain_dname(zone->apex),
					     param_rr);
	if (hashed_apex == NULL) {
		log_msg(LOG_ERR,
			"hashed name memory allocation failure");
		return ENOMEM;
	}
	
	domain = domain_table_find(namedb->domains,
				   hashed_apex);
	if (!domain) {
		log_msg(LOG_ERR,
			"%s NSEC3PARAM entry %u: "
			"no hash(apex)",
			dname_to_string(domain_dname(zone->apex),
					NULL),
			rr_num);
		log_msg(LOG_DEBUG,
			"hash(apex)= %s",
			dname_to_string(hashed_apex,
					NULL));
		return ENOERROR;
	}
	
	nsec3_rrset = domain_find_rrset(domain,
					zone,
					TYPE_NSEC3);
	if (nsec3_rrset == NULL) {
		log_msg(LOG_ERR,
			"%s NSEC3PARAM entry %u: "
			"hash(apex) has no NSEC3 RRset",
			dname_to_string(domain_dname(zone->apex),
					NULL),
			rr_num);
		log_msg(LOG_DEBUG,
			"hash(apex)= %s",
			dname_to_string(hashed_apex,
					NULL));
		return ENOERROR;
	}

	*pp_nsec3_rrset = nsec3_rrset;

	return ENOERROR;
}

/**
 ************************************************************************
 * Check settings in zone apex NSEC3PARAM.
 * Hash algorithm must be OK.
 * A NSEC3 RR with SOA bit must map to the zone apex.
 */

int
find_zone_nsec3(namedb_type *namedb,
		zone_type *zone,
		struct rr **pp_rr)
{
	region_type *tmp_region;
	rrset_type *param_rrset;

	uint32_t i;

	int error = ENOERROR;

	if (pp_rr == NULL) {
		return EINVAL;
	}

	*pp_rr = NULL;

	param_rrset = domain_find_rrset(zone->apex,
					zone,
					TYPE_NSEC3PARAM);
	if (param_rrset == NULL) {
		return ENOERROR;
	}

	tmp_region = region_create(xalloc,
				  free);
	if (tmp_region == NULL) {
		return ENOMEM;
	}

	for (i = 0; i < param_rrset->rr_count; i++) {
		rr_type *param_rr;

		rrset_type *nsec3_rrset;
		uint32_t j;

		unsigned char const *salt1;
		int saltlen1;
		int iter1;

		param_rr = &param_rrset->rrs[i];

		error = nsec3_check_param_rrset(zone,
						i,
						param_rr);
		if (error != ENOERROR) {
			continue;
		}

		error = find_zone_nsec3_param_rrset(tmp_region,
						    namedb,
						    zone,
						    i,
						    param_rr,
						    &nsec3_rrset);
		if (error != ENOERROR) {
			break;
		}

		if (nsec3_rrset == NULL) {
			continue;
		}

		detect_nsec3_params(param_rr,
				    &salt1,
				    &saltlen1,
				    &iter1);

		/* find SOA bit enabled nsec3, with the same settings */
		for (j = 0; j < nsec3_rrset->rr_count; j++) {
			struct rr *nsec3_rr;

			unsigned char const *salt2;
			int saltlen2;
			int iter2;

			nsec3_rr = &nsec3_rrset->rrs[j];

			if (nsec3_has_soa(nsec3_rr) == 0) {
				continue;
			}

			/* check params OK. Ignores the optout bit. */
			detect_nsec3_params(nsec3_rr,
					    &salt2,
					    &saltlen2,
					    &iter2);

			if ((saltlen1 == saltlen2) &&
			    (iter1 == iter2) &&
			    (rdata_atom_data(param_rr->rdatas[0])[0] == /* algo */
			     rdata_atom_data(nsec3_rr->rdatas[0])[0]) &&
			    (memcmp(salt1,
				    salt2,
				    saltlen1) == 0)) {
				/* found it */
				DEBUG(DEBUG_QUERY, 1, (LOG_INFO,
					"detected NSEC3 for zone %s iter=%d",
					dname_to_string(domain_dname(zone->apex),
							NULL),
					iter2));

				region_destroy(tmp_region);

				*pp_rr = nsec3_rr;

				return ENOERROR;
			}
		}

		log_msg(LOG_ERR,
			"%s NSEC3PARAM entry %u: hash(apex) no NSEC3 with SOAbit",
			dname_to_string(domain_dname(zone->apex),
					NULL),
			i);
	}

	region_destroy(tmp_region);

	return ENOERROR;
}

/**
 ************************************************************************
 */

/* check that the rrset has an NSEC3 that uses the same parameters as the
   zone is using. Pass NSEC3 rrset, and zone must have nsec3_rrset set.
   if you pass NULL then 0 is returned. */
static int
nsec3_rrset_params_ok(rr_type* base,
		      rrset_type* rrset)
{
	rdata_atom_type* prd;
	size_t i;

	if (rrset == NULL) {
		return 0; /* without rrset, no matching params either */
	}

	if (base == NULL) {
		assert(rrset->zone != NULL);
		assert(rrset->zone->nsec3_soa_rr != NULL);

		base = rrset->zone->nsec3_soa_rr;
	}

	prd = base->rdatas;
	for (i=0; i<rrset->rr_count; ++i) {
		rdata_atom_type* rd;

		rd = rrset->rrs[i].rdatas;
		assert(rrset->rrs[i].type == TYPE_NSEC3);
		if (rdata_atom_data(rd[0])[0] ==
		    rdata_atom_data(prd[0])[0] && /* hash algo */
		    rdata_atom_data(rd[2])[0] ==
		    rdata_atom_data(prd[2])[0] && /* iterations 0 */
		    rdata_atom_data(rd[2])[1] ==
		    rdata_atom_data(prd[2])[1] && /* iterations 1 */
		    rdata_atom_data(rd[3])[0] ==
		    rdata_atom_data(prd[3])[0] && /* salt length */
		    memcmp(rdata_atom_data(rd[3])+1,
			   rdata_atom_data(prd[3])+1,
			   rdata_atom_data(rd[3])[0])
		    == 0 ) {
			/* this NSEC3 matches nsec3 parameters from zone */
			return 1;
		}
	}
	return 0;
}

/**
 ************************************************************************
 */

#ifdef   NSEC3_HASH_DEBUG

static int
nsec3_dump_hash_to_domain(namedb_type *db,
			  zone_type *zone)
{
	rbnode_t *node;

	struct domain *domain;
	struct domain *hash_domain;

	char domain_name[1024];
	char hash_name[1024];

	char filename[1024];

	FILE *fp;

	if ((db == NULL) ||
	    (zone == NULL)) {
		return EINVAL;
	}

	snprintf(filename,
		 1024,
		 "/tmp/htd.%s",
		 dname_to_string(domain_dname(zone->apex),
				 NULL));

	if ((fp = fopen(filename, "w")) == NULL) {
		log_msg(LOG_ERR,
			"Unable to open file \"%s\"",
			filename);			
		return EINVAL;
	}

	if (zone->nsec3_domains == NULL) {
		fclose(fp);
		return ENOERROR;
	}

	node = rbtree_first(zone->nsec3_domains);

	while (node != RBTREE_NULL) {
		struct nsec3_domain *nsec3_domain =
			(struct nsec3_domain *) node;

		hash_domain = nsec3_domain->nsec3_domain;
		domain = nsec3_domain->covers;

		if (domain != NULL) {
			fprintf(fp,
				"%s = H(%s)\n",
				dname_to_string_r(domain_dname(hash_domain),
						  NULL,
						  hash_name),
				dname_to_string_r(domain_dname(domain),
						  NULL,
						  domain_name));
		}

		node = rbtree_next(node);
	}

	fclose(fp);

	return ENOERROR;
}

/**
 ************************************************************************
 */

static int
nsec3_dump_domain_to_hash(namedb_type *db,
			  zone_type *zone)
{
	struct domain *domain;
	struct domain *hash_domain;

	char domain_name[1024];
	char hash_name[1024];

	char filename[1024];

	FILE *fp;

	if ((db == NULL) ||
	    (zone == NULL)) {
		return EINVAL;
	}

	snprintf(filename,
		 1024,
		 "/tmp/dth.%s",
		 dname_to_string(domain_dname(zone->apex),
				 NULL));

	if ((fp = fopen(filename, "w")) == NULL) {
		log_msg(LOG_ERR,
			"Unable to open file \"%s\"",
			filename);			
		return EINVAL;
	}

	if (zone->nsec3_domains == NULL) {
		fclose(fp);
		return ENOERROR;
	}

	domain = zone->apex;

	while ((domain != NULL) &&
	       (dname_is_subdomain(domain_dname(domain),
				   domain_dname(zone->apex)) != 0)) {
		struct domain *domain_zone_apex;

		domain_zone_apex = domain_find_zone_apex(domain);

		if ((domain_zone_apex != NULL) &&
		    (domain_zone_apex == zone->apex) &&
		    (domain_is_glue(domain,
				    zone) == 0) &&
		    (domain->nsec3_cover != NULL)) {
			hash_domain = domain->nsec3_cover;

			fprintf(fp,
				"H(%s) = %s\n",
				dname_to_string_r(domain_dname(domain),
						  NULL,
						  domain_name),
				dname_to_string_r(domain_dname(hash_domain),
						  NULL,
						  hash_name));
		}

		domain = domain_next(domain);
	}

	fclose(fp);

	return ENOERROR;
}

#endif   /* NSEC3_HASH_DEBUG */

/**
 ************************************************************************
 * The heart of new NSEC3 prehash.  Uses zone->nsec3_domains.
 */

static int
nsec3_find_cover(namedb_type *db,
		 zone_type *zone,
		 dname_type const *hash_dname,
		 struct nsec3_domain **pp_nsec3_domain)
{
	rbnode_t *node;
	int exact;

	if (pp_nsec3_domain == NULL) {
		return 0;
	}
	*pp_nsec3_domain = NULL;

	if (zone->nsec3_domains == NULL) {
		return 0;
	}

	exact = rbtree_find_less_equal(zone->nsec3_domains,
				       hash_dname,
				       &node);
	if (node == NULL) {
		/* (node == NULL) ==> (exact == 0) */
		node = rbtree_last(zone->nsec3_domains);
	}

	while (node != RBTREE_NULL) {
		struct nsec3_domain *nsec3_domain =
			(struct nsec3_domain *) node;

		struct rrset *nsec3_rrset;

		nsec3_rrset = domain_find_rrset(nsec3_domain->nsec3_domain,
						zone,
						TYPE_NSEC3);
		if (nsec3_rrset == NULL) {
			/*
			 * RRset in zone->nsec3_domains whose type != NSEC3
			 * If we get here, something is seriously wrong!
			 */
			return 0;
		}

		if (nsec3_rrset_params_ok(NULL,
					  nsec3_rrset) != 0) {
			*pp_nsec3_domain = nsec3_domain;
			return exact;
		}

		exact = 0; /* No match, so we're looking for closest match */
		node = rbtree_previous(node);
	}

	/*
	 * If we reach this point, *pp_nsec3_domain == NULL.  This should
	 * never happen since the zone should have one NSEC3 record with
	 * the SOA bit set, which matches a NSEC3PARAM RR in the zone.
	 */

	return exact;
}

/**
 ************************************************************************
 */

static int
prehash_domain(namedb_type *db,
	       zone_type *zone,
	       domain_type *domain,
	       region_type *region)
{
	struct nsec3_domain *nsec3_domain = NULL;
	dname_type const *hash_dname;

	int exact;

	domain->nsec3_cover = NULL;

	hash_dname = nsec3_hash_dname(region,
				      zone,
				      domain_dname(domain));
	if (hash_dname == NULL) {
		return ENOMEM;
	}

	exact = nsec3_find_cover(db,
				 zone,
				 hash_dname,
				 &nsec3_domain);

	if ((nsec3_domain != NULL) &&
	    (exact != 0)) {
		nsec3_domain->covers = domain;

		domain->nsec3_cover = nsec3_domain->nsec3_domain;
	}

	return ENOERROR;
}

/**
 ************************************************************************
 * This exists because a parent zone could have different NSEC3PARAM's
 * than a child, thus a delegation point could hash to two different
 * names for the two zones.
 */

#if 0

static int
prehash_ds(namedb_type *db,
	   zone_type *zone,
	   domain_type *domain,
	   region_type *region)
{
	struct nsec3_domain *nsec3_domain;
	domain_type *hash_domain;
	dname_type const *hash_dname;

	int exact;

	hash_dname = nsec3_hash_dname(region,
				      zone,
				      domain_dname(domain));
	if (hash_dname == NULL) {
		return ENOMEM;
	}
	
	exact = nsec3_find_cover(db,
				 zone,
				 hash_dname,
				 &nsec3_domain);

	hash_domain = nsec3_domain->nsec3_domain;

	domain->nsec3_ds_parent_is_exact = (exact != 0);
	domain->nsec3_ds_parent_cover = hash_domain;

	return ENOERROR;
}
#endif

/**
 ************************************************************************
 */

struct domain *
find_last_nsec3_domain(struct zone *zone)
{
	rbnode_t *node;

	if (zone->nsec3_domains == NULL) {
		return NULL;
	}

	node = rbtree_last(zone->nsec3_domains);

	if (node == RBTREE_NULL) {
		return NULL;
	}

	return ((struct nsec3_domain *) node)->nsec3_domain;
}

/**
 ************************************************************************
 */

int
prehash_zone_incremental(struct namedb *db,
			 struct zone *zone)
{
	int error = ENOERROR;

	region_type *temp_region;

	rbnode_t *node;

	/* find zone NSEC3PARAM settings */
	error = find_zone_nsec3(db,
				zone,
				&zone->nsec3_soa_rr);

	if (error != ENOERROR) {
		return error;
	}

	if (zone->nsec3_soa_rr == NULL) {
		zone->nsec3_last = NULL;
		return ENOERROR;
	}

	if (db->nsec3_mod_domains == NULL) {
		return ENOERROR;
	}

	zone->nsec3_last = find_last_nsec3_domain(zone);

	temp_region = region_create(xalloc,
				    free);

	if (temp_region == NULL) {
		return ENOMEM;
	}

	node = rbtree_first(db->nsec3_mod_domains);

	while (node != RBTREE_NULL) {
		struct nsec3_mod_domain *nsec3_mod_domain;
		struct domain *domain_zone_apex;
		struct domain *walk;

		nsec3_mod_domain = (struct nsec3_mod_domain *) node;

		walk = nsec3_mod_domain->domain;

		if ((walk == NULL) ||
		    (dname_is_subdomain(domain_dname(walk),
					domain_dname(zone->apex)) == 0)) {
			node = rbtree_next(node);
			continue;
		}

		if (walk->nsec3_cover != NULL) {
			node = rbtree_next(node);
			continue;
		}

		/* Empty Terminal */
		if (walk->is_existing == 0) {
			walk->nsec3_cover = NULL;
			node = rbtree_next(node);
			continue;
		}

		/*
		 * Don't hash NSEC3 only nodes, unless possibly
		 * part of a weird case where node is empty nonterminal
		 * requiring NSEC3 but node name also is the hashed
		 * node name of another node requiring NSEC3.
		 * NSEC3 Empty Nonterminal with NSEC3 RRset present.
		 */
		if (domain_has_only_NSEC3(walk,
					  zone) != 0) {
			struct domain *next_domain;

			next_domain = domain_next(walk);

			if ((next_domain == NULL) ||
			    (next_domain->parent != walk)) {
				walk->nsec3_cover = NULL;
				node = rbtree_next(node);
				continue;
			}
		}

		/*
		 * Identify domain nodes that belong to the zone
		 * which are not glue records.  What if you hit a
		 * record that's in two zones but which has no
		 * cut point between the zones. Not valid but
		 * someone is gonna try it sometime.
		 * This implementation doesn't link an NSEC3
		 * record to the domain.
		 */
		domain_zone_apex = domain_find_zone_apex(walk);

		if ((domain_zone_apex != NULL) &&
		    (domain_zone_apex == zone->apex) &&
		    (domain_is_glue(walk,
				    zone) == 0)) {
			error = prehash_domain(db,
					       zone,
					       walk,
					       temp_region);

			region_free_all(temp_region);
		}

#if 0
		/*
		 *
		 * prehash the DS (parent zone)
		 *
		 * Took me forever to figure this one out.  At a
		 * zone cut point, it's quite possible that the
		 * server serves both the parent and the child zone.
		 * Unfortunately the parent and the child zone could
		 * have completely different NSEC3PARAM's and so
		 * the NSEC3 record for the delegation point in the
		 * parent could be completely different from that for
		 * the child.  But we only have one "cover".
		 * NSD kept another DS_cover.
		 */
		if (domain_find_rrset(walk,
				      zone,
				      TYPE_DS) ||
		    (domain_find_rrset(walk,
				       zone,
				       TYPE_NS) &&
		     (walk != zone->apex))) {
			error = prehash_ds(db,
					   zone,
					   walk,
					   temp_region);
			region_free_all(temp_region);
		}
#endif

		node = rbtree_next(node);
	}

	namedb_nsec3_mod_domains_destroy(db);

	region_destroy(temp_region);

#ifdef   NSEC3_HASH_DEBUG
	nsec3_dump_hash_to_domain(db, zone);
	nsec3_dump_domain_to_hash(db, zone);
#endif

	return error;
}

/**
 ************************************************************************
 */

int
prehash_zone(struct namedb *db,
	     struct zone *zone)
{
	int error = ENOERROR;

	domain_type *walk;

	region_type *temp_region;

	/* find zone NSEC3PARAM settings */
	error = find_zone_nsec3(db,
				zone,
				&zone->nsec3_soa_rr);

	if (error != ENOERROR) {
		return error;
	}

	if (zone->nsec3_soa_rr == NULL) {
		zone->nsec3_last = NULL;
		return ENOERROR;
	}

	zone->nsec3_last = find_last_nsec3_domain(zone);

	temp_region = region_create(xalloc,
				    free);

	if (temp_region == NULL) {
		return ENOMEM;
	}

	/* go through entire zone */
	walk = zone->apex;

	while ((error == ENOERROR) &&
	       (walk != NULL) &&
	       (dname_is_subdomain(domain_dname(walk),
				   domain_dname(zone->apex)) != 0)) {
		struct domain *domain_zone_apex;

	if (walk->nsec3_cover != NULL) {
			walk = domain_next(walk);
			continue;
		}

		/* Empty Terminal */
		if (walk->is_existing == 0) {
			walk->nsec3_cover = NULL;
			walk = domain_next(walk);
			continue;
		}

		/*
		 * Don't hash NSEC3 only nodes, unless possibly
		 * part of a weird case where node is empty nonterminal
		 * requiring NSEC3 but node name also is the hashed
		 * node name of another node requiring NSEC3.
		 * NSEC3 Empty Nonterminal with NSEC3 RRset present.
		 */
		if (domain_has_only_NSEC3(walk,
					  zone) != 0) {
			struct domain *next_domain;

			next_domain = domain_next(walk);

			if ((next_domain == NULL) ||
			    (next_domain->parent != walk)) {
				walk->nsec3_cover = NULL;
				walk = domain_next(walk);
				continue;
			}
		}

		/*
		 * Identify domain nodes that belong to the zone
		 * which are not glue records.  What if you hit a
		 * record that's in two zones but which has no
		 * cut point between the zones. Not valid but
		 * someone is gonna try it sometime.
		 * This implementation doesn't link an NSEC3
		 * record to the domain.
		 */
		domain_zone_apex = domain_find_zone_apex(walk);

		if ((domain_zone_apex != NULL) &&
		    (domain_zone_apex == zone->apex) &&
		    (domain_is_glue(walk,
				    zone) == 0)) {
			error = prehash_domain(db,
					       zone,
					       walk,
					       temp_region);

			region_free_all(temp_region);
		}

#if 0
		/*
		 *
		 * prehash the DS (parent zone)
		 *
		 * Took me forever to figure this one out.  At a
		 * zone cut point, it's quite possible that the
		 * server serves both the parent and the child zone.
		 * Unfortunately the parent and the child zone could
		 * have completely different NSEC3PARAM's and so
		 * the NSEC3 record for the delegation point in the
		 * parent could be completely different from that for
		 * the child.  But we only have one "cover".
		 * NSD kept another DS_cover.
		 */
		if (domain_find_rrset(walk,
				      zone,
				      TYPE_DS) ||
		    (domain_find_rrset(walk,
				       zone,
				       TYPE_NS) &&
		     (walk != zone->apex))) {
			error = prehash_ds(db,
					   zone,
					   walk,
					   temp_region);
			region_free_all(temp_region);
		}
#endif

		walk = domain_next(walk);
	}

	region_destroy(temp_region);

#ifdef   NSEC3_HASH_DEBUG
	nsec3_dump_hash_to_domain(db, zone);
	nsec3_dump_domain_to_hash(db, zone);
#endif

	return error;
}

/**
 ************************************************************************
 */

int
prehash(struct namedb *db,
	int update_zones_only)
{
	zone_type *zone;

	time_t start;
	time_t end;

	uint32_t count = 0;

	int error = ENOERROR;

	start = time(NULL);

	zone = db->zones;

	while ((zone != NULL) &&
	       (error == ENOERROR)) {

		if ((update_zones_only == 0) ||
		    (zone->updated != 0)) {

			error = prehash_zone(db,
					     zone);

			if (zone->nsec3_soa_rr != NULL) {
				count++;
			}
		}

		zone = zone->next;
	}

	end = time(NULL);

	if (count > 0) {
		VERBOSITY(1, (LOG_INFO,
			      "nsec3-prepare took %d "
			      "seconds for %u zones.",
			      (int)(end-start),
			      count));
	}

	return error;
}

/**
 ************************************************************************
 */

static int
nsec3_hash_and_find_cover(struct region *region,
			  struct namedb *db,
			  struct dname const *domain_dname,
			  struct zone *zone,
			  int *exact,
			  struct domain **pp_domain)
{
	dname_type const *hash_dname;

	struct nsec3_domain *nsec3_domain;

	*pp_domain = NULL;
	*exact = 0;

	hash_dname = nsec3_hash_dname(region,
				      zone,
				      domain_dname);
	if (hash_dname == NULL) {
		return ENOMEM;
	}

	*exact = nsec3_find_cover(db,
				  zone,
				  hash_dname,
				  &nsec3_domain);

	if (nsec3_domain != NULL) {
		*pp_domain = nsec3_domain->nsec3_domain;
	}

	return ENOERROR;
}

/**
 ************************************************************************
 */

static int
nsec3_hash_and_find_wild_cover(struct region *region,
			       struct namedb *db,
			       struct domain *domain,
			       struct zone *zone,
			       int *exact,
			       struct domain **pp_domain)
{
	int error;

	struct dname const *wcard_child;

	/* find cover for *.domain for wildcard denial */
	error = dname_make_wildcard(region,
				    domain_dname(domain),
				    &wcard_child);
	if (error != ENOERROR) {
		return error;
	}

	error = nsec3_hash_and_find_cover(region,
					  db,
					  wcard_child,
					  zone,
					  exact,
					  pp_domain);

	if ((*exact != 0) &&
	    (domain_wildcard_child(domain) == NULL)) {
		/* We found an exact match for the *.domain NSEC3 hash,
		 * but the domain wildcard child (*.domain) does not exist.
		 * Thus there is a hash collision. It will cause servfail
		 * for NXdomain queries below this domain.
		 */
		log_msg(LOG_WARNING,
			"collision of wildcard denial for %s. "
			"Sign zone with different salt to remove collision.",
			dname_to_string(domain_dname(domain),
					NULL));
	}

	return error;
}

/*
 ************************************************************************
 */

static void
nsec3_add_rrset(struct query *query,
		struct answer *answer,
		rr_section_type section,
		struct domain* domain)
{
	if (domain != NULL) {
		rrset_type* rrset = domain_find_rrset(domain,
						      query->zone,
						      TYPE_NSEC3);
		if (rrset != NULL) {
			answer_add_rrset(answer,
					 section,
					 domain,
					 rrset);
		}
	}
}

/**
 ************************************************************************
 * this routine does hashing at query-time.
 */

static int
nsec3_add_nonexist_proof(struct query *query,
			 struct answer *answer,
			 struct domain *encloser,
			 struct namedb *db,
			 dname_type const *qname)
{
	dname_type const *to_prove;

	struct domain *proof_cover;
	
	int error;
	int exact;

	uint8_t label_count;

	if (encloser == NULL) {
		return ENOERROR;
	}

	/* if query=a.b.c.d encloser=c.d. then proof needed for b.c.d. */
	/* if query=a.b.c.d encloser=*.c.d. then proof needed for b.c.d. */

	label_count = (dname_label_match_count(qname,
					       domain_dname(encloser)) + 1);

	to_prove = dname_partial_copy(query->region,
				      qname,
				      label_count);
	if (to_prove == NULL) {
		return ENOMEM;
	}

	/* generate proof that one label below closest encloser does not exist */
	error = nsec3_hash_and_find_cover(query->region,
					  db,
					  to_prove,
					  query->zone,
					  &exact,
					  &proof_cover);
	if (error != ENOERROR) {
		return error;
	}

	if (exact != 0) {
		/* exact match, hash collision */
		/* the hashed name of the query corresponds to an existing name. */
		log_msg(LOG_ERR,
			"nsec3 hash collision for name=%s",
			dname_to_string(to_prove,
					NULL));

		RCODE_SET(query->packet,
			  RCODE_SERVFAIL);
	}
	else {
		/* cover proves the qname does not exist */
		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				proof_cover);
	}

	return ENOERROR;
}

/**
 ************************************************************************
 */

static int
nsec3_add_closest_encloser_proof(struct query *query,
				 struct answer *answer,
				 struct domain *closest_encloser,
				 struct namedb *db,
				 dname_type const *qname)
{
	int error;

	if (closest_encloser == NULL)
		return ENOERROR;

	/* prove that below closest encloser nothing exists */
	error = nsec3_add_nonexist_proof(query,
					 answer,
					 closest_encloser,
					 db,
					 qname);
	if (error != ENOERROR) {
		return error;
	}

	/* proof that closest encloser exists */
	if (closest_encloser->nsec3_cover != NULL) {
		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				closest_encloser->nsec3_cover);
	}

	return ENOERROR;
}

/**
 ************************************************************************
 */

int
nsec3_answer_wildcard(struct query *query,
		      struct answer *answer,
		      struct domain *wildcard,
		      struct namedb *db,
		      dname_type const *qname)
{
	int error;

	if ((wildcard == NULL) ||
	    (query->zone->nsec3_soa_rr == NULL)) {
		return ENOERROR;
	}

	error = nsec3_add_nonexist_proof(query,
					 answer,
					 wildcard,
					 db,
					 qname);

	return error;
}

/**
 ************************************************************************
 */

static int
nsec3_add_ds_proof(struct query *query,
		   struct answer *answer,
		   struct domain *domain)
{
	struct domain *ds_parent_cover;

	int exact;
	int error;

	/* assert we are above the zone cut */
	assert(domain != query->zone->apex);

	/* Find the parents cover NSEC3 domain for DS */
	error = nsec3_hash_and_find_cover(query->region,
					  NULL,
					  domain_dname(domain),
					  query->zone,
					  &exact,
					  &ds_parent_cover);
	if (error != ENOERROR) {
		return error;
	}

	if (exact == 0) {
		/* prove closest provable encloser */

		domain_type *prev_parent = NULL;
		domain_type *parent = domain->parent;

		while ((parent != NULL) &&
		       (parent->nsec3_cover == NULL)) {
			prev_parent = parent;
			parent = parent->parent;
		}

		if (parent == NULL) {
			/* Serious bad stuff. */
			/* parent zone apex must be provable, thus this ends */
			return EINVAL;
		}

		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				parent->nsec3_cover);

		/*
		 * If prev_parent is not NULL, we took more than one step up the
		 * parent chain to find a provable parent, this means that the
		 * one below it has no exact nsec3. Disprove it.
		 */

		if (prev_parent != NULL) {
			struct domain *prev_parent_cover;

			error = nsec3_hash_and_find_cover(query->region,
							  NULL,
							  domain_dname(prev_parent),
							  query->zone,
							  &exact,
							  &prev_parent_cover);
			if (error != ENOERROR) {
				return error;
			}

			nsec3_add_rrset(query,
					answer,
					AUTHORITY_SECTION,
					prev_parent_cover);
		}
	}

	/* use NSEC3 record from above the zone cut. */
	/* add optout range from parent zone */
	/* note: no check of optout bit, resolver checks it */
	nsec3_add_rrset(query,
			answer,
			AUTHORITY_SECTION,
			ds_parent_cover);

	return ENOERROR;
}

/**
 ************************************************************************
 */

int
nsec3_answer_nodata(struct query *query,
		    struct answer *answer,
		    struct domain *original)
{
	int error = ENOERROR;

	if (query->zone->nsec3_soa_rr == NULL) {
		return ENOERROR;
	}

	if (query->qtype == TYPE_DS) {
		/* nodata when asking for secure delegation */

		if (original == query->zone->apex) {
			/* DS at zone apex, but server not authoritative for parent zone */
			/* so answer at the child zone level */

			if (original->nsec3_cover != NULL) { /* exact */
				nsec3_add_rrset(query,
						answer,
						AUTHORITY_SECTION,
						original->nsec3_cover);
			}
		}
		else {
			/* query->zone must be the parent zone */
			error = nsec3_add_ds_proof(query,
						   answer,
						   original);
		}
	}
	else if ((original == original->wildcard_child_closest_match) &&
		 label_is_wildcard(dname_name(domain_dname(original)))) {
		/* the nodata is result from a wildcard match */
		/* denial for wildcard is already there */
		/* add parent proof to have a closest encloser proof for wildcard parent */

		struct domain *original_cover;

		int exact;

		if ((original->parent != NULL) &&
		    (original->parent->nsec3_cover != NULL)) { /* parent cover exact */
			nsec3_add_rrset(query,
					answer,
					AUTHORITY_SECTION,
					original->parent->nsec3_cover);
		}

		/* proof for wildcard itself */
		original_cover = original->nsec3_cover;

		if (original_cover == NULL) { /* not exact */
			error = nsec3_hash_and_find_cover(query->region,
							  NULL,
							  domain_dname(original),
							  query->zone,
							  &exact,
							  &original_cover);
			if (error != ENOERROR) {
				return error;
			}
		}

		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				original_cover);
	}
	else {
		/* add nsec3 to prove rrset does not exist */
		if (original->nsec3_cover != NULL) { /* exact */
			nsec3_add_rrset(query,
					answer,
					AUTHORITY_SECTION,
					original->nsec3_cover);
		}
	}

	return error;
}

/**
 ************************************************************************
 */

int
nsec3_answer_delegation(struct query *query,
			struct answer *answer)
{
	int error;

	if (query->zone->nsec3_soa_rr == NULL) {
		return ENOERROR;
	}

	error = nsec3_add_ds_proof(query,
				   answer,
				   query->delegation_domain);

	return error;
}

/**
 ************************************************************************
 */

int
nsec3_answer_authoritative(struct domain **match,
			   struct query *query,
			   struct answer *answer,
			   struct domain *closest_encloser,
			   struct namedb *db,
			   dname_type const *qname)
{
	int error;
	int exact;

	struct domain *cover_domain;

	assert(match != NULL);

	if (query->zone->nsec3_soa_rr == NULL) {
		return ENOERROR;
	}

	/* there is a match, this has 1 RRset, which is NSEC3, but qtype is not. */
	if ((*match != NULL) &&
#if 0
	    query->qtype != TYPE_NSEC3 &&
#endif
	    domain_has_only_NSEC3(*match,
				  query->zone)) {
		/* act as if the NSEC3 domain did not exist, name error */
		*match = NULL;

		/* all nsec3s are directly below the apex, that is closest encloser */
		if (query->zone->apex->nsec3_cover != NULL) { /* exact */
			nsec3_add_rrset(query,
					answer,
					AUTHORITY_SECTION,
					query->zone->apex->nsec3_cover);
		}

		/* disprove the nsec3 record. */
		cover_domain = closest_encloser->nsec3_cover;
		if (cover_domain == NULL) {
			error = nsec3_hash_and_find_cover(query->region,
							  db,
							  domain_dname(closest_encloser),
							  query->zone,
							  &exact,
							  &cover_domain);
			if (error != ENOERROR) {
				return error;
			}
		}

		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				cover_domain);

		/* disprove a wildcard */
		error = nsec3_hash_and_find_wild_cover(query->region,
						       db,
						       query->zone->apex,
						       query->zone,
						       &exact,
						       &cover_domain);
		if (error != ENOERROR) {
			return error;
		}

		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				cover_domain);

		if (domain_wildcard_child(query->zone->apex)) {
			/* wildcard exists below the domain */
			/* wildcard and nsec3 domain clash. server failure. */
			RCODE_SET(query->packet,
				  RCODE_SERVFAIL);
		}
	}
	else if (*match == NULL) {
		/* name error, domain does not exist */
		error = nsec3_add_closest_encloser_proof(query,
							 answer,
							 closest_encloser,
							 db,
							 qname);
		if (error != ENOERROR) {
			return error;
		}
		
		error = nsec3_hash_and_find_wild_cover(query->region,
						       db,
						       closest_encloser,
						       query->zone,
						       &exact,
						       &cover_domain);
		if (error != ENOERROR) {
			return error;
		}

		nsec3_add_rrset(query,
				answer,
				AUTHORITY_SECTION,
				cover_domain);
	}

	return ENOERROR;
}

#endif /* NSEC3 */

