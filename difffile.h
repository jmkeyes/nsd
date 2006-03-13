/*
 * difffile.h - nsd.diff file handling header file. Read/write diff files.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef DIFFFILE_H
#define DIFFFILE_H

#include <config.h>
#include "rbtree.h"
#include "namedb.h"
#include "options.h"

#define DIFF_FILE_MAGIC "NSDdfV01"
#define DIFF_FILE_MAGIC_LEN 8

#define DIFF_PART_IXFR ('I'<<24 | 'X'<<16 | 'F'<<8 | 'R')
#define DIFF_PART_SURE ('S'<<24 | 'U'<<16 | 'R'<<8 | 'E')

/* write an xfr packet data to the diff file, type=IXFR.
   The diff file is created if necessary. */
void diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt);

/* write a commit packet to the diff file, type=SURE.
   The zone data (preceding ixfr packets) are committed */
void diff_write_commit(const char* zone, uint32_t new_serial, 
	uint8_t commit, const char* log_msg,
	nsd_options_t* opt);

/* check if the crc in the nsd.db is the same in memory as on disk.
   returns 1 if different. 0 if the same. returns -1 on error. */
int db_crc_different(namedb_type* db);

/* read the diff file and apply to the database in memory.
   It will attempt to skip bad data. 
   returns 0 on an unrecoverable error. */
int diff_read_file(namedb_type* db, nsd_options_t* opt);

#endif /* DIFFFILE_H */
