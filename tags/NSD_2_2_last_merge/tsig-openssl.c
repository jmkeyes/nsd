/*
 * tsig-openssl.h -- Interface to OpenSSL for TSIG support.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#if defined(TSIG) && defined(HAVE_SSL)

#include <openssl/hmac.h>

#include "tsig-openssl.h"
#include "tsig.h"

static void *create_context(region_type *region);
static void init_context(void *context,
			 tsig_algorithm_type *algorithm,
			 tsig_key_type *key);
static void update(void *context, const void *data, size_t size);
static void final(void *context, uint8_t *digest, size_t *size);

int
tsig_openssl_init(region_type *region)
{
	tsig_algorithm_type *md5_algorithm;
	const EVP_MD *hmac_md5_algorithm;

	OpenSSL_add_all_digests();
	hmac_md5_algorithm = EVP_get_digestbyname("md5");
	if (!hmac_md5_algorithm) {
		log_msg(LOG_ERR, "hmac-md5 algorithm not available");
		return 0;
	}

	md5_algorithm = (tsig_algorithm_type *) region_alloc(
		region, sizeof(tsig_algorithm_type));
	md5_algorithm->short_name = "hmac-md5";
	md5_algorithm->wireformat_name
		= dname_parse(region, "hmac-md5.sig-alg.reg.int.");
	if (!md5_algorithm->wireformat_name) {
 		log_msg(LOG_ERR, "cannot parse MD5 algorithm name");
		return 0;
	}
	md5_algorithm->maximum_digest_size = EVP_MAX_MD_SIZE;
	md5_algorithm->data = hmac_md5_algorithm;
	md5_algorithm->hmac_create_context = create_context;
	md5_algorithm->hmac_init_context = init_context;
	md5_algorithm->hmac_update = update;
	md5_algorithm->hmac_final = final;
	tsig_add_algorithm(md5_algorithm);
	
	return 1;
}

static void
cleanup_context(void *data)
{
	HMAC_CTX *context = (HMAC_CTX *) data;
	HMAC_CTX_cleanup(context);
}

static void *
create_context(region_type *region)
{
	HMAC_CTX *context
		= (HMAC_CTX *) region_alloc(region, sizeof(HMAC_CTX));
	region_add_cleanup(region, cleanup_context, context);
	HMAC_CTX_init(context);
	return context;
}

static void
init_context(void *context,
			  tsig_algorithm_type *algorithm,
			  tsig_key_type *key)
{
	HMAC_CTX *ctx = (HMAC_CTX *) context;
	const EVP_MD *md = (const EVP_MD *) algorithm->data;
	HMAC_Init_ex(ctx, key->data, key->size, md, NULL);
}

static void
update(void *context, const void *data, size_t size)
{
	HMAC_CTX *ctx = (HMAC_CTX *) context;
	HMAC_Update(ctx, (unsigned char *) data, (int) size);
}

static void
final(void *context, uint8_t *digest, size_t *size)
{
	HMAC_CTX *ctx = (HMAC_CTX *) context;
	unsigned len = (unsigned) *size;
	HMAC_Final(ctx, digest, &len);
	*size = (size_t) len;
}

#endif /* defined(TSIG) && defined(HAVE_SSL) */
