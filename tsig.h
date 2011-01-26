/*
 * tsig.h -- TSIG definitions (RFC 2845).
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _TSIG_H_
#define _TSIG_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"
#include "dname.h"

#define TSIG_ERROR_NOERROR  0
#define TSIG_ERROR_BADSIG   16
#define TSIG_ERROR_BADKEY   17
#define TSIG_ERROR_BADTIME  18

#define TSIG_HMAC_MD5       157
#define TSIG_HMAC_SHA1      158
#define TSIG_HMAC_SHA256    159

typedef struct tsig_algorithm tsig_algorithm_type;
typedef struct tsig_key tsig_key_type;
typedef struct tsig_record tsig_record_type;

enum tsig_status
{
	TSIG_NOT_PRESENT,
	TSIG_OK,
	TSIG_ERROR
};
typedef enum tsig_status tsig_status_type;

struct tsig_lookup_struct_table
{
	uint8_t id;
	const char* short_name;
};
typedef struct tsig_lookup_struct_table tsig_lookup_algorithm_table;

/*
 * A TSIG HMAC algorithm, such as hmac-md5.
 */
struct tsig_algorithm
{
	/*
	 * Short name of the algorithm, such as "hmac-md5".
	 */
	const char *short_name;

	/*
	 * Full wireformat name of the algorithm, such as
	 * "hmac-md5.sig-alg.reg.int."
	 */
	const dname_type *wireformat_name;

	/*
	 * The maximum size of a digest generated by this algorithm.
	 */
	size_t maximum_digest_size;

	/*
	 * Algorithm implementation specific data.
	 */
	const void *data;

	/*
	 * Create a new HMAC context.
	 */
	void *(*hmac_create_context)(region_type *region);

	/*
	 * Initialize an HMAC context with the specified algorithm and
	 * key.
	 */
	void  (*hmac_init_context)(void *context,
				   tsig_algorithm_type *algorithm,
				   tsig_key_type *key);

	/*
	 * Update the HMAC context with the specified data.
	 */
	void  (*hmac_update)(void *context, const void *data, size_t size);

	/*
	 * Generate the final digest.  DIGEST points to a buffer of at
	 * least maximum_digest_size bytes.
	 */
	void  (*hmac_final)(void *context, uint8_t *digest, size_t *size);
};

/*
 * A TSIG key used to sign and verify packets.
 */
struct tsig_key
{
	const dname_type *name;
	size_t            size;
	const uint8_t    *data;
};

struct tsig_record
{
	tsig_status_type     status;
	size_t               position;
	size_t               response_count;
	size_t               updates_since_last_prepare;
	void                *context;
	tsig_algorithm_type *algorithm;
	tsig_key_type       *key;
	size_t               prior_mac_size;
	uint8_t             *prior_mac_data;

	/* TSIG RR data is allocated in the rr_region.  */
	region_type      *rr_region;
	region_type	 *context_region;
	const dname_type *key_name;
	const dname_type *algorithm_name;
	uint16_t          signed_time_high;
	uint32_t          signed_time_low;
	uint16_t          signed_time_fudge;
	uint16_t          mac_size;
	uint8_t          *mac_data;
	uint16_t          original_query_id;
	uint16_t          error_code;
	uint16_t          other_size;
	uint8_t          *other_data;
};

/*
 * Initialize the TSIG module (including TSIG implementation modules
 * such as tsig-openssl).
 */
int tsig_init(region_type *region);

/*
 * Add the specified key to the TSIG key table.
 */
void tsig_add_key(tsig_key_type *key);

/*
 * Add the specified algorithm to the TSIG algorithm table.
 */
void tsig_add_algorithm(tsig_algorithm_type *algorithm);

/*
 * Find an HMAC algorithm based on its short name.
 */
tsig_algorithm_type *tsig_get_algorithm_by_name(const char *name);

/*
 * Find an HMAC algorithm based on its identifier.
 */
tsig_algorithm_type *tsig_get_algorithm_by_id(uint8_t alg);

/*
 * Return a descriptive error message based on the TSIG error code.
 */
const char *tsig_error(int error_code);

/*
 * Create the tsig record internal structure. Allocs it.
 * Call init_record afterwards before doing more with it.
 *
 * The region is used to attach a cleanup function that destroys the tsig.
 */
void tsig_create_record(tsig_record_type* tsig,
			region_type* region);

/*
 * Like tsig_create_record, with custom region settings.
 * The size params are used to customise the rr_region and context_region.
 */
void tsig_create_record_custom(tsig_record_type* tsig,
			region_type* region,
			size_t chunk_size,
			size_t large_object_size,
			size_t initial_cleanup_size);

/*
 * Call this before starting to analyze or signing a sequence of
 * packets.
 *
 * ALGORITHM and KEY are optional and are only needed if you want to
 * sign the initial query.  Otherwise the key and algorithm are looked
 * up in the algorithm and key table when a received TSIG RR is
 * processed.
 */
void tsig_init_record(tsig_record_type *data,
		      tsig_algorithm_type *algorithm,
		      tsig_key_type *key);

/*
 * Validate the TSIG RR key and algorithm from the TSIG RR.  Otherwise
 * update the TSIG error code.  The MAC itself is not validated.
 *
 * Returns non-zero if the key and algorithm could be validated.
 */
int tsig_from_query(tsig_record_type *tsig);

/*
 * Prepare TSIG for signing of a query.  This initializes TSIG with
 * the algorithm and key stored in the TSIG record.
 */
void tsig_init_query(tsig_record_type *tsig, uint16_t original_query_id);

/*
 * Prepare TSIG for performing an HMAC calculation.  If the TSIG
 * contains a prior HMAC it is inserted first into the hash
 * calculation.
 */
void tsig_prepare(tsig_record_type *tsig);

/*
 * Add the first LENGTH octets of PACKET to the TSIG hash, replacing
 * the PACKET's id with the original query id from TSIG.  If the query
 * is a response the TSIG response count is incremented.
 */
void tsig_update(tsig_record_type *tsig, buffer_type *packet, size_t length);

/*
 * Finalize the TSIG record by hashing the TSIG data.  If the TSIG
 * response count is greater than 1 only the timers are hashed.
 * Signed time is set to the current time.  The TSIG record can be
 * added to a packet using tsig_append_rr().
 *
 * The calculated MAC is also stored as the prior MAC, so it can be
 * used as a running MAC.
 */
void tsig_sign(tsig_record_type *tsig);

/*
 * Verify the calculated MAC against the MAC in the TSIG RR.
 *
 * The calculated MAC is also stored as the prior MAC, so it can be
 * used as a running MAC.
 */
int tsig_verify(tsig_record_type *tsig);

/*
 * Find the TSIG RR in QUERY and parse it if present.  Store the
 * parsed results in TSIG.
 *
 * Returns non-zero if no parsing error occurred, use the tsig->status
 * field to find out if the TSIG record was present.
 */
int tsig_find_rr(tsig_record_type *tsig, buffer_type *packet);

/*
 * Call this to analyze the TSIG RR starting at the current location
 * of PACKET. On success true is returned and the results are stored
 * in TSIG.
 *
 * Returns non-zero if no parsing error occurred, use the tsig->status
 * field to find out if the TSIG record was present.
 */
int tsig_parse_rr(tsig_record_type *tsig, buffer_type *packet);

/*
 * Append the TSIG record to the response PACKET.
 */
void tsig_append_rr(tsig_record_type *tsig, buffer_type *packet);

/*
 * The amount of space to reserve in the response for the TSIG data
 * (if required).
 */
size_t tsig_reserved_space(tsig_record_type *tsig);

/*
 * status or error_code must already be in error.
 * prepares content for error packet.
 */
void tsig_error_reply(tsig_record_type *tsig);

/*
 * compare tsig algorithm names case insensitive.
 */
int tsig_strlowercmp(const char* str1, const char* str2);

/*
 * cleanup tsig openssl stuff.
 */
void tsig_finalize(void);

#ifdef MEMCHECK
void memcheck_tsig_record_clean(region_type* region, tsig_record_type *tsig);
#endif

#endif /* _TSIG_H_ */
