/*
 * $Id: hash.h,v 1.10 2003/03/20 10:31:25 alexis Exp $
 *
 * hash.h -- generic non-dynamic hash
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
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

#ifndef _HASH_H_
#define	_HASH_H_

#if !defined(__P)
#	if defined(__STDC__)
#		define __P(protos)     protos          /* full-blown ANSI C */
# 	else
# 		define __P(protos)
# 	endif
#endif

#ifndef	NULL
#define	NULL	(void *)0
#endif

#define	MIN_HASH_SIZE	16

typedef struct hnode_t hnode_t;
struct hnode_t {
	hnode_t *next;
	void	*key;
	void	*data;
};

typedef struct hash_t hash_t;
struct hash_t {
	unsigned long size;		/* The size of the table. */
	unsigned long count;		/* The number of the nodes in the tree */
	unsigned long collisions;	/* Number of collisions */
	
	/* Private elements for iterating the table */
	hnode_t *_node;
	unsigned _i;

	void *(*mallocf)(size_t);		/* Malloc function */
	int (*cmp) (void *, void *);			/* Compare function */
	unsigned long (*hash)(void *);	/* The hash function */

	/* The hash table */
	hnode_t	*table;
};

#define	HASH_WALK(hash, k, d) \
	for((hash)->_node = hash_first(hash);\
		(hash)->_node != hash_last(hash) && \
		((k) = (hash)->_node->key) && ((d) = (hash)->_node->data); \
		(hash)->_node = hash_next(hash))

#define	hash_last(h) NULL

/* hash.c */
hash_t *hash_create(void *(*mallocf)(size_t), int (*cmpf)(void *, void *), unsigned long (*hashf)(void *), unsigned long size);
void *hash_insert(hash_t *hash, void *key, void *data, int overwrite);
void *hash_search(hash_t *hash, void *key);
void hash_destroy(hash_t *hash, int freekeys, int freedata);
unsigned long hashf(char *key);
hnode_t *hash_first(hash_t *hash);
hnode_t *hash_next(hash_t *hash);


#endif /* _HASH_H_ */