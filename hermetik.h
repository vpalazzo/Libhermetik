//--------------------------------- License ------------------------------------
//
//	Copyright (c) 2018 Victor Palazzo <palazzov@sheridancollege.ca>
//
//	Permission to use, copy, modify, and distribute this software for any
//	purpose with or without fee is hereby granted, provided that the above
//	copyright notice and this permission notice appear in all copies.
//
//	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//------------------------------------------------------------------------------

//--------------------------------- README -------------------------------------
//
//	First off, why is the README inside of this header file? At the time of this
//	writing (12-12-2018 @ 23:36), I've seen a fair amount of projects over my
//	11 years of development. The one common trait I have noticed is that there
// 	is an unnecessary amount of files and repeating of information. Case in
//	point; the canonical 'LICENSE' file. This file contains the license under
//	which the containing project is distributed; it's also in the heading of
//	every applicable source file contained within said project - e.g.
//	directly above this section. That's one redundant file.
//
//	Next, the 'CHANGELOG'; why is this contained in a separate file? It contains
//	information pertaining to the various versions of the project. Why not keep
//	it with the core header file? This same header file should contain your
//	project's version tracking numbers (major.minor.patch), e.g.
//
//		HERMETIK_VERSION_MAJOR
//		HERMETIK_VERSION_MINOR
//		HERMETIK_VERSION_PATCH
//
//	I've chosen to centralize this information as well - that's two redundant
//	files eliminated.
//
//	Next up, the 'CONTRIBUTORS' file: this file typically contains the name(s)
//	of the original author(s) of the given project, as well as contributors,
//	if any, to the code. If you've contributed to the code, your name deserves
//	to be with the code - not in a separate file. 
//
//	Last but not least, the 'README' file. This file typically contains
//	information about the project: supported operating systems, required/
//	included libraries - if any - as well as build instructions. Again, a file
//	containing information about how to build the given project - why not
//	include this with the core header file? The 'README' is no good without
//	the source code, which is exactly why I've included it here. Now, on to the
//	traditional information:
//	____________________________________________________________________________
//
//	Project Name:	libhermetik
//	Version:		v0.2.1
//	License:		ISC
//
//	About:
//
//		LibHermetik is a Public-Key Infrastructure Management library, written
//		in ANSI-C, implementing and extending the LibSodium and SQLite
//		libraries. The main goals of LibHermetik are:
//
//			- Provide an easy to use PKI Management library.
//			- Provide an alternative to the proprietary solutions offered by
//			  BlackBerry (e.g. BES) and the like.
//			- Provide a clean code base for developers to learn about the
//			  implementation, deployment, and management of a PKI.
//
//	Required/ Included Libraries:
//
//		[ 0 ] sqlite3 	(v3.25.2)
//		[ 1 ] libsodium (v1.0.16)
//				- Must be built for your specific environment. A tarball
//				  of the source code used to build libsodium, which this
//				  version of libhermetik has been tested against, is included.
//				- See https://download.libsodium.org/doc/installation for
//				  more information.
//				- See the file 'Makefile.debug' for examples of how to link
//				  your executable against the libsodium library.
//
//
//	How do I use libhermetik in my project?
//
//		- Simply copy the files 'hermetik.h' and 'hermetik.c' to your project's
//		  source directory. Include the 'hermetik.h' file, and you're done. You
//		  can now call functions within libhermetik. Note, you must also have
//		  the SQLite and libsodium libraries included in your project as well.
//		  For SQLite, you may simply copy the folder 'sqlite3' to your project's
//		  source directory; this folder contains the SQLite amalagamation files.
//
//		  With regards to libsodium, you'll have to build the library yourself,
//		  for your particular architecture. You can also look at the file
//		  'Makefile.debug' for examples of how to link your executable with
//		  libsodium. 
//
//		  See https://download.libsodium.org/doc/installation for more
//		  information.
//                                         	 
//
//------------------------------------------------------------------------------

//------------------------------ Change Log ------------------------------------
//
//	v0.1.0
//
//		- Created the following files:
//
//			> hermetik.h
//			> hermetik.c
//			> Makefile.debug
//			> main.c
//
//		- Implemented a benchmark() function in main.c
//
//	v0.2.0
//
//		- Added the 'Change Log' section.
//		- Memory allocations are now done using calloc(), instead of malloc().
//		  Segmentation faults were noticed when executing thousands of calls to
//		  malloc() - via a loop - on macOS v10.14.1. Investigation with LLDB
//		  showed that memmove() was being called by the OS, just prior to
//		  us calling memset(), but after a successful call to malloc(),
//		  resulting in a corrupted, or dangling pointer. This behaviour was
//		  discovered by using a 'watch' variable in LLDB to observe the value
//		  of the suspected corrupted pointer, and catch any attempt to modify
//		  the address pointed to by said pointer.
//		- Removed code required to debug malloc() related issues.
//
//	v0.2.1
//
//		- Patched hermetik_note_set_body() to handle note bodies <= 100 bytes.
//
//	vX.X.X
//
//		[ ] TODO: Implement v3 and v4 functions.
//		[ ] TODO: Benchmark against in-memory database; e.g. ':memory:'
//		[ ] TODO: 'Keychain' (combination, multi-key) encryption.
//					> 'Onion'-like, or layered encryption scheme.
//					> Requires the exact keys in the exact order, in order
//					  to decrypt.
//		[ ] TODO: Implement quantum-resistant encryption (NTRU)
//					> This was implemented in a pre-alpha version. The issue is
//					  that the decryption was failing on iOS devices. The issue
//					  was noted on various online bug trackers, no resolution at
//				      the time of this writing (16-12-2018). Maybe we can debug
//					  with LLDB if it is not an algorithm related issue.
//					> Implement function calls exclusively for macOS?
//		[ ]	TODO: Dynamic blocks; e.g. setting the block data size at runtime.
//
//------------------------------------------------------------------------------

//------------------------------- Contributors ---------------------------------
//
//	Original Author: 	Victor Palazzo
//	Email:				palazzov@sheridancollege.ca
//
//------------------------------------------------------------------------------

//------------------------------ Define Guards ---------------------------------
#ifndef hermetik_h
#define hermetik_h

//---------------------------- Include Statements ------------------------------

// Include required standard C headers
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

// Include the sqlite3 library
#include <sqlite3.h>

// Include the utils header for sodium
#include <utils.h>

// Include the sodium library
#include <sodium.h>

// Project Version
#define HERMETIK_VERSION		"0.2.1"
#define HERMETIK_VERSION_MAJOR	0
#define HERMETIK_VERSION_MINOR	2
#define HERMETIK_VERSION_PATCH	1

//------------------------ Buffer Size Definitions -----------------------------

#define HERMETIK_BUFLEN_1_KB	((size_t)(1024))
#define HERMETIK_BUFLEN_1_MB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 2)))
#define HERMETIK_BUFLEN_1_GB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 3)))
#define HERMETIK_BUFLEN_1_TB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 4)))
#define HERMETIK_BUFLEN_1_PB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 5)))
#define HERMETIK_BUFLEN_1_EB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 6)))
#define HERMETIK_BUFLEN_1_ZB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 7)))
#define HERMETIK_BUFLEN_1_YB	((size_t)(powl(HERMETIK_BUFLEN_1_KB, 8)))
#define HERMETIK_BUFLEN_MAX_SIZE SIZE_MAX

//------------------------------- Typedefs -------------------------------------

#define HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES	(crypto_box_PUBLICKEYBYTES)
#define HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES	(crypto_box_SECRETKEYBYTES)

#define HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES \
	((HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES * 2) + 1)

#define HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES \
	((HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES * 2) + 1)

#define HERMETIK_KEYPAIR_COMPARE_IDENTICAL			(0)
#define HERMETIK_KEYPAIR_COMPARE_PUBLIC_KEY_DIFF	(1)
#define HERMETIK_KEYPAIR_COMPARE_PRIVATE_KEY_DIFF	(2)
#define HERMETIK_KEYPAIR_COMPARE_NO_MATCH			(3)
#define HERMETIK_KEYPAIR_COMPARE_ERROR				(-1)

//	A hermetik_keypair represents a public-key pair.
//
typedef struct hermetik_keypair
{
	unsigned char *public_key;
	unsigned char *private_key;
} hermetik_keypair;

void hermetik_init_keypair(hermetik_keypair *kp);

void hermetik_init_keypair_with_keypair(hermetik_keypair *dst_kp,
										const hermetik_keypair *src_kp);

void hermetik_free_keypair(hermetik_keypair *kp);

bool hermetik_keypair_generate_keys(hermetik_keypair *kp);

void hermetik_keypair_public_key_to_hex(const hermetik_keypair *kp,
										char *hex);

void hermetik_keypair_private_key_to_hex(const hermetik_keypair *kp,
										 char *hex);

int hermetik_keypair_compare(const hermetik_keypair *kp,
							 const hermetik_keypair *kp2);

void hermetik_keypair_copy(hermetik_keypair *dst_kp,
						   const hermetik_keypair *src_kp);

void hermetik_keypair_zero_out(hermetik_keypair *kp);

//______________________________________________________________________________

#define CREATE_KEYPAIR_TABLE_SQL_STATEMENT \
"CREATE TABLE IF NOT EXISTS KEYPAIR "\
"(ID INTEGER PRIMARY KEY AUTOINCREMENT, "\
"PRIVATE_KEY TEXT, "\
"PUBLIC_KEY TEXT, "\
"COMMENT TEXT)"

#define DROP_KEYPAIR_TABLE_SQL_STATEMENT \
"DROP TABLE IF EXISTS KEYPAIR"

#define INSERT_KEYPAIR_RECORD_SQL_STATEMENT \
"INSERT INTO KEYPAIR (PRIVATE_KEY, PUBLIC_KEY, COMMENT) VALUES (?,?,?)"

#define SELECT_KEYPAIR_RECORD_BY_ID_SQL_STATEMENT \
"SELECT ID, PRIVATE_KEY, PUBLIC_KEY, COMMENT FROM KEYPAIR "\
"WHERE ID = ?"

#define SELECT_ALL_KEYPAIR_RECORDS_SQL_STATEMENT \
"SELECT ID, PRIVATE_KEY, PUBLIC_KEY, COMMENT FROM KEYPAIR"

#define SELECT_KEYPAIR_RECORD_COUNT_SQL_STATEMENT \
"SELECT COUNT(*) FROM KEYPAIR"

#define DELETE_KEYPAIR_RECORD_BY_ID_SQL_STATEMENT \
"DELETE FROM KEYPAIR WHERE ID = ?"

#define DELETE_ALL_KEYPAIR_RECORDS \
"DELETE FROM KEYPAIR"

#define HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES	(100)

//	A hermetik_sqlite3_keypair is an extension of the hermetik_keypair type.
//	This extension allows persistence via a SQLite database.
//
typedef struct hermetik_sqlite3_keypair
{
	unsigned int db_id;
	hermetik_keypair *kp;
	char *comment;
} hermetik_sqlite3_keypair;

void hermetik_init_sqlite3_keypair(hermetik_sqlite3_keypair *skp);

void hermetik_init_sqlite3_keypair_with_keypair(hermetik_sqlite3_keypair *skp,
												const hermetik_keypair *kp);

void hermetik_free_sqlite3_keypair(hermetik_sqlite3_keypair *skp);

bool hermetik_sqlite3_keypair_set_comment(hermetik_sqlite3_keypair *skp,
										  const char *cmnt,
										  size_t cmnt_len);

bool hermetik_create_sqlite3_keypair_table(const char *db_path);

// TODO
bool hermetik_create_sqlite3_keypair_table_v2(const sqlite3 *db);

bool hermetik_drop_sqlite3_keypair_table(const char *db_path);

// TODO
bool hermetik_drop_sqlite3_keypair_table_v2(const sqlite3 *db);

bool hermetik_get_sqlite3_keypair_by_id(const char *db_path,
					   					const unsigned int db_id,
									    hermetik_sqlite3_keypair *skp);

// TODO
bool hermetik_get_sqlite3_keypair_by_id_v2(const sqlite3 *db,
					   					   const unsigned int db_id,
									       hermetik_sqlite3_keypair *skp);

unsigned int hermetik_get_sqlite3_keypair_count(const char *db_path);

// TODO
unsigned int hermetik_get_sqlite3_keypair_count_v2(const sqlite3 *db);

unsigned int hermetik_get_all_sqlite3_keypairs(const char *db_path,
										   hermetik_sqlite3_keypair *(*skps)[]);

unsigned int hermetik_get_all_sqlite3_keypairs_v2(const char *db_path,
											hermetik_sqlite3_keypair **skps);

// TODO
unsigned int hermetik_get_all_sqlite3_keypairs_v3(const sqlite3* db,
											hermetik_sqlite3_keypair **);

bool hermetik_save_sqlite3_keypair(const char *db_path,
								   const hermetik_sqlite3_keypair *skp);

// TODO
bool hermetik_save_sqlite3_keypair_v2(const sqlite3* db,
								      const hermetik_sqlite3_keypair *skp);

bool hermetik_delete_sqlite3_keypair(const char *db_path,
									 const hermetik_sqlite3_keypair *skp);

// TODO
bool hermetik_delete_sqlite3_keypair_v2(const sqlite3 *db,
										const hermetik_sqlite3_keypair *skp);

bool hermetik_delete_sqlite3_keypair_by_id(const char *db_path,
										  unsigned int db_id);

// TODO
bool hermetik_delete_sqlite3_keypair_by_id_v2(const sqlite3 db,
											  unsigned int db_id);

//______________________________________________________________________________

#define HERMETIK_BLOCK_DATA_SIZE_BYTES		(100)
#define HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES \
	(HERMETIK_BLOCK_DATA_SIZE_BYTES + crypto_box_SEALBYTES)

#define HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES \
	((HERMETIK_BLOCK_DATA_SIZE_BYTES * 2) + 1)

#define HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES \
	((HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES * 2) + 1)

#define HERMETIK_BLOCK_COMPARE_IDENTICAL		(0)
#define HERMETIK_BLOCK_COMPARE_DATA_DIFF		(1)
#define HERMETIK_BLOCK_COMPARE_ENC_DATA_DIFF	(3)
#define HERMETIK_BLOCK_COMPARE_NO_MATCH			(4)
#define HERMETIK_BLOCK_COMPARE_ERROR			(-1)

//	The hermetik_block type is the basis for more complex types requiring
//	public-key encryption. A hermetik_block represents a 'block' of data,
//	with pointers to both the encrypted and un-encrypted forms of said data.
//
typedef struct hermetik_block
{
	unsigned char *data;
	unsigned char *encrypted_data;
} hermetik_block;

void hermetik_init_block(hermetik_block *b);

void hermetik_free_block(hermetik_block *b);

bool hermetik_block_encrypt_with_keypair(hermetik_block *b,
									 	 const hermetik_keypair *kp);

bool hermetik_block_decrypt_with_keypair(hermetik_block *b,
									 	 const hermetik_keypair *kp);

void hermetik_block_zero_out(hermetik_block *b);

void hermetik_block_set_data(hermetik_block *b,
							 const unsigned char *d,
							 size_t dlen);

void hermetik_block_set_encrypted_data(hermetik_block *b,
									   const unsigned char *d,
									   size_t dlen);

void hermetik_block_data_to_hex(const hermetik_block *b,
								char *hex);

void hermetik_block_encrypted_data_to_hex(const hermetik_block *b,
										  char *hex);

// TODO: optimized version of hermetik_block_compare() with switch statement
int hermetik_block_compare_v2(const hermetik_block *b,
						   	  const hermetik_block *b2);

int hermetik_block_compare(const hermetik_block *b,
						   const hermetik_block *b2);

bool hermetik_block_compare_data(const hermetik_block *b,
						   		 const hermetik_block *b2);

bool hermetik_block_compare_encrypted_data(const hermetik_block *b,
										   const hermetik_block *b2);

void hermetik_block_copy(hermetik_block *b,
						 const hermetik_block *src_b);

void hermetik_block_copy_data(hermetik_block *b,
							  const hermetik_block *src_b);

void hermetik_block_copy_encrypted_data(hermetik_block *b,
										const hermetik_block *src_b);

//______________________________________________________________________________

#define HERMETIK_NOTE_BODY_SIZE_BLOCKS	(10)
#define HERMETIK_NOTE_BODY_SIZE_BYTES \
	(HERMETIK_NOTE_BODY_SIZE_BLOCKS * HERMETIK_BLOCK_DATA_SIZE_BYTES)

#define HERMETIK_NOTE_BODY_AS_HEX_SIZE_BYTES \
	((HERMETIK_NOTE_BODY_SIZE_BYTES * 2) + 1)

#define HERMETIK_NOTE_ENC_BODY_SIZE_BYTES \
	(HERMETIK_NOTE_BODY_SIZE_BLOCKS * HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES)

#define HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES \
	((HERMETIK_NOTE_ENC_BODY_SIZE_BYTES * 2) + 1)

#define HERMETIK_NOTE_TITLE_SIZE_BYTES (HERMETIK_BLOCK_DATA_SIZE_BYTES)
#define HERMETIK_NOTE_TITLE_AS_HEX_SIZE_BYTES \
	((HERMETIK_NOTE_TITLE_SIZE_BYTES * 2) + 1)

#define HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES \
	(HERMETIK_NOTE_TITLE_SIZE_BYTES + crypto_box_SEALBYTES)

#define HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES \
	((HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES * 2) + 1)

//	The hermetik_note type represents a note that offers public-key encryption
//	and decryption of its title and body (content).
//
typedef struct hermetik_note
{
	hermetik_block *title;
	hermetik_block *body[HERMETIK_NOTE_BODY_SIZE_BLOCKS];
} hermetik_note;

//	The hermetik_note_compare_summary type is used in the comparison of
//	different hermetik_notes. It is a complex type that solves the issue of
//	multiple function calls to compare notes. 
//
typedef struct hermetik_note_compare_summary
{
	bool identical;
	bool titles_differ;
	bool bodies_differ;
	bool enc_titles_differ;
	bool enc_bodies_differ;
	bool error_occurred;
} hermetik_note_compare_summary;

void hermetik_init_note_compare_summary(hermetik_note_compare_summary *ncs);

void hermetik_free_note_compare_summary(hermetik_note_compare_summary *ncs);

void hermetik_init_note(hermetik_note *hn);

void hermetik_free_note(hermetik_note *hn);

void hermetik_note_set_title(hermetik_note *hn,
							 const unsigned char *d,
							 size_t dlen);

void hermetik_note_set_encrypted_title(hermetik_note *hn,
									   const unsigned char *d,
									   size_t dlen);

void hermetik_note_set_body(hermetik_note *hn,
							const unsigned char *d,
							size_t dlen);

void hermetik_note_set_encrypted_body(hermetik_note *hn,
									  const unsigned char *d,
									  size_t dlen);

bool hermetik_note_encrypt_title_with_keypair(hermetik_note *hn,
											  const hermetik_keypair *kp);

bool hermetik_note_encrypt_body_with_keypair(hermetik_note *hn,
											 const hermetik_keypair *kp);

bool hermetik_note_encrypt_with_keypair(hermetik_note *hn,
										const hermetik_keypair *kp);

bool hermetik_note_decrypt_title_with_keypair(hermetik_note *hn,
											  const hermetik_keypair *kp);

bool hermetik_note_decrypt_body_with_keypair(hermetik_note *hn,
											 const hermetik_keypair *kp);

bool hermetik_note_decrypt_with_keypair(hermetik_note *hn,
										const hermetik_keypair *kp);

void hermetik_note_title_to_hex(const hermetik_note *hn,
								char *hex);

void hermetik_note_encrypted_title_to_hex(const hermetik_note *hn,
										  char *hex);

// TODO: dynamic memory allocation
void hermetik_note_body_to_hex_v2(const hermetik_note *hn,
							   char *hex);

void hermetik_note_body_to_hex(const hermetik_note *hn,
							   char *hex);

void hermetik_note_encrypted_body_to_hex(const hermetik_note *hn,
										 char *hex);

void hermetik_note_zero_out_title(hermetik_note *hn);

void hermetik_note_zero_out_body(hermetik_note *hn);

void hermetik_note_zero_out(hermetik_note *hn);

void hermetik_note_copy_title(const hermetik_note *hn,
							  unsigned char *dst);

void hermetik_note_copy_body(const hermetik_note *hn,
							 unsigned char *dst);

void hermetik_note_copy_encrypted_title(const hermetik_note *hn,
								   		unsigned char *dst);

void hermetik_note_copy_encrypted_body(const hermetik_note *hn,
								  	   unsigned char *dst);

void hermetik_note_copy(hermetik_note *dst,
						const hermetik_note *src);

bool hermetik_note_compare_titles(const hermetik_note *hn,
								  const hermetik_note *hn2);

bool hermetik_note_compare_bodies(const hermetik_note *hn,
								  const hermetik_note *hn2);

bool hermetik_note_compare_encrypted_titles(const hermetik_note *hn,
										    const hermetik_note *hn2);

bool hermetik_note_compare_encrypted_bodies(const hermetik_note *hn,
										    const hermetik_note *hn2);

void hermetik_note_compare(const hermetik_note *hn,
						   const hermetik_note *hn2,
						   hermetik_note_compare_summary *ncs);

void hermetik_note_hex_dump_body(const hermetik_note *hn);

void hermetik_note_hex_dump_encrypted_body(const hermetik_note *hn);

//______________________________________________________________________________

#define CREATE_NOTE_TABLE_SQL_STATEMENT \
"CREATE TABLE IF NOT EXISTS NOTE "\
"(ID INTEGER PRIMARY KEY AUTOINCREMENT, "\
"TITLE TEXT, "\
"BODY TEXT)"

#define DROP_NOTE_TABLE_SQL_STATEMENT \
"DROP TABLE IF EXISTS NOTE"

#define INSERT_NOTE_RECORD_SQL_STATEMENT \
"INSERT INTO NOTE (TITLE, BODY) VALUES (\"%s\", \"%s\")"

#define INSERT_NOTE_RECORD_SQL_STATEMENT_V2 \
"INSERT INTO NOTE (TITLE, BODY) VALUES (?,?)"

#define SELECT_NOTE_RECORD_BY_ID_SQL_STATEMENT \
"SELECT ID, TITLE, BODY FROM NOTE WHERE ID = ?"

#define SELECT_ALL_NOTE_RECORDS_SQL_STATEMENT \
"SELECT ID, TITLE, BODY FROM NOTE"

#define SELECT_NOTE_RECORD_COUNT_SQL_STATEMENT \
"SELECT COUNT(*) FROM NOTE"

#define DELETE_NOTE_RECORD_BY_ID_SQL_STATEMENT \
"DELETE FROM NOTE WHERE ID = ?"

#define DELETE_ALL_NOTE_RECORDS \
"DELETE FROM NOTE"

//	The hermetik_sqlite3_note type is an extension of the hermetik_note type.
//	This extension offers persistance capabilites via a SQLite database.
//
typedef struct hermetik_sqlite3_note
{
	unsigned int db_id;
	hermetik_note *hn;
} hermetik_sqlite3_note;

void hermetik_init_sqlite3_note(hermetik_sqlite3_note *sn);

// TODO
void hermetik_init_sqlite3_note_with_note(hermetik_sqlite3_note *sn,
										  const hermetik_note *hn);

void hermetik_free_sqlite3_note(hermetik_sqlite3_note *sn);

bool hermetik_create_sqlite3_note_table(const char *db_path);

// TODO
bool hermetik_create_sqlite3_note_table_v2(const sqlite3 *db);

bool hermetik_drop_sqlite3_note_table(const char *db_path);

// TODO
bool hermetik_drop_sqlite3_note_table_v2(const sqlite3 *db);

bool hermetik_get_sqlite3_note_by_id(const char *db_path,
									 const unsigned int db_id,
									 hermetik_sqlite3_note *sn);

// TODO
bool hermetik_get_sqlite3_note_by_id_v2(const sqlite3 *db,
										const unsigned int db_id,
										hermetik_sqlite3_note *sn);

unsigned int hermetik_get_sqlite3_note_count(const char *db_path);

// TODO
unsigned int hermetik_get_sqlite3_note_count_v2(const sqlite3 *db);

unsigned int hermetik_get_all_sqlite3_notes(const char *db_path,
											hermetik_sqlite3_note *(*sns)[]);


unsigned int hermetik_get_all_sqlite3_notes_v2(const char *db_path,
											   hermetik_sqlite3_note **sns);

// TODO
unsigned int hermetik_get_all_sqlite3_notes_v3(const sqlite3 *db,
											   hermetik_sqlite3_note **sns);

bool hermetik_save_sqlite3_note(const char *db_path,
							    const hermetik_sqlite3_note *sn);

bool hermetik_save_sqlite3_note_v2(const char *db_path,
								   const hermetik_sqlite3_note *sn);

// TODO
bool hermetik_save_sqlite3_note_v3(const sqlite3 *db,
								   const hermetik_sqlite3_note *sn);

bool hermetik_update_sqlite3_note(const char *db_path,
								  const hermetik_sqlite3_note *sn);

// TODO
bool hermetik_update_sqlite3_note_v2(const sqlite3 *db,
									 const hermetik_sqlite3_note *sn);

bool hermetik_delete_sqlite3_note(const char *db_path,
								  const hermetik_sqlite3_note *sn);

// TODO
bool hermetik_delete_sqlite3_note_v2(const sqlite3 *db,
									 const hermetik_sqlite3_note *sn);

bool hermetik_delete_sqlite3_note_by_id(const char *db_path,
										unsigned int db_id);

// TODO
bool hermetik_delete_sqlite3_note_by_id_v2(const sqlite3 *db,
										   unsigned int db_id);

//______________________________________________________________________________

#define HERMETIK_MAIL_ADDRESS_USERNAME_SIZE_BYTES \
	(HERMETIK_BLOCK_DATA_SIZE_BYTES)

#define HERMETIK_MAIL_ADDRESS_USERNAME_AS_HEX_SIZE_BYTES \
	((HERMETIK_MAIL_ADDRESS_USERNAME_SIZE_BYTES * 2) + 1)

#define HERMETIK_MAIL_ADDRESS_ENC_USERNAME_SIZE_BYTES \
	(HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES)

#define HERMETIK_MAIL_ADDRESS_ENC_USERNAME_AS_HEX_SIZE_BYTES \
	((HERMETIK_MAIL_ADDRESS_ENC_USERNAME_SIZE_BYTES * 2) + 1)

#define HERMETIK_MAIL_ADDRESS_HOSTNAME_SIZE_BYTES \
	(HERMETIK_BLOCK_DATA_SIZE_BYTES)

#define HERMETIK_MAIL_ADDRESS_HOSTNAME_AS_HEX_SIZE_BYTES \
	((HERMETIK_MAIL_ADDRESS_HOSTNAME_SIZE_BYTES * 2) + 1)

#define HERMETIK_MAIL_ADDRESS_ENC_HOSTNAME_SIZE_BYTES \
	(HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES)

#define HERMETIK_MAIL_ADDRESS_ENC_HOSTNAME_AS_HEX_SIZE_BYTES \
	((HERMETIK_MAIL_ADDRESS_ENC_HOSTNAME_SIZE_BYTES * 2) + 1)

#define HERMETIK_MAIL_ADDRESS_PUBLIC_KEY_SIZE_BYTES \
	(HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES)

#define HERMETIK_MAIL_ADDRESS_PUBLIC_KEY_AS_HEX_SIZE_BYTES \
	((HERMETIK_MAIL_ADDRESS_PUBLIC_KEY_SIZE_BYTES * 2) + 1)

// TODO **
typedef struct hermetik_mail_address
{
	hermetik_block *username;
	hermetik_block *hostname;
	int port;
	unsigned char *public_key;
} hermetik_mail_address;

// TODO **
void hermetik_init_mail_address(hermetik_mail_address *hma);

// TODO
void hermetik_init_mail_address_with_address(hermetik_mail_address *hma,
										     const hermetik_mail_address *src);

// TODO **
void hermetik_free_mail_address(hermetik_mail_address *hma);

// TODO **
void hermetik_mail_address_username_to_hex(const hermetik_mail_address *hma,
										   char *hex);

// TODO **
void hermetik_mail_address_enc_username_to_hex(const hermetik_mail_address *hma,
											   char *hex);

// TODO **
void hermetik_mail_address_hostname_to_hex(const hermetik_mail_address *hma,
										   char *hex);

// TODO **
void hermetik_mail_address_enc_hostname_to_hex(const hermetik_mail_address *hma,
											   char *hex);

// TODO
void hermetik_mail_address_set_username(hermetik_mail_address *hma,
										const unsigned char *d,
										size_t dlen);
// TODO
void hermetik_mail_address_set_enc_username(hermetik_mail_address *hma,
										    const unsigned char *d,
											size_t dlen);

// TODO
void hermetik_mail_address_set_hostname(hermetik_mail_address *hma,
										const unsigned char *d,
										size_t dlen);
// TODO
void hermetik_mail_address_set_enc_hostname(hermetik_mail_address *hma,
											const unsigned char *d,
											size_t dlen);

// TODO
void hermetik_mail_address_set_port(hermetik_mail_address *hma,
									int port_num);

// TODO
void hermetik_mail_address_set_public_key(hermetik_mail_address *hma,
										  const unsigned char *d);

// TODO
void hermetik_mail_address_zero_username(hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_zero_hostname(hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_zero_public_key(hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_zero(hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_enc_username(hermetik_mail_address *hma,
										const hermetik_keypair *kp);
// TODO
void hermetik_mail_address_enc_hostname(hermetik_mail_address *hma,
										const hermetik_keypair *kp);
// TODO
void hermetik_mail_address_enc(hermetik_mail_address *hma,
							   const hermetik_keypair *kp);
// TODO
void hermetik_mail_address_dec_username(hermetik_mail_address *hma,
										const hermetik_keypair *kp);
// TODO
void hermetik_mail_address_dec_hostname(hermetik_mail_address *hma,
										const hermetik_keypair *kp);
// TODO
void hermetik_mail_address_dec(hermetik_mail_address *hma,
							   const hermetik_keypair *kp);

// TODO
void hermetik_mail_address_cpy_username(unsigned char *dst,
										const hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_cpy_enc_username(unsigned char *dst,
											const hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_cpy_hostname(unsigned char *dst,
										const hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_cpy_enc_hostname(unsigned char *dst,
											const hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_cpy_public_key(unsigned char *dst,
										  const hermetik_mail_address *hma);

// TODO
void hermetik_mail_address_cpy(hermetik_mail_address *dst,
							   const hermetik_mail_address *src);

// TODO
typedef struct hermetik_mail_address_comparator
{
	bool identical;
	bool error_occurred;
	bool usernames_differ;
	bool hostnames_differ;
	bool encrypted_usernames_differ;
	bool encrypted_hostnames_differ;
	bool ports_differ;
	bool public_keys_differ;
} hermetik_mail_address_comparator;

// TODO
void hermetik_init_mail_address_comparator(
								hermetik_mail_address_comparator *mac);

// TODO
void hermetik_free_mail_address_comparator(
								hermetik_mail_address_comparator *mac);

// TODO
bool hermetik_mail_address_cmp_usernames(const hermetik_mail_address *hma,
										 const hermetik_mail_address *hma2);

// TODO
bool hermetik_mail_address_cmp_hostnames(const hermetik_mail_address *hma,
										 const hermetik_mail_address *hma2);

// TODO
bool hermetik_mail_address_cmp_enc_usernames(const hermetik_mail_address *hma,
											 const hermetik_mail_address *hma2);

// TODO
bool hermetik_mail_address_cmp_enc_hostnames(const hermetik_mail_address *hma,
											 const hermetik_mail_address *hma2);

// TODO
bool hermetik_mail_address_cmp_ports(const hermetik_mail_address *hma,
									 const hermetik_mail_address *hma2);

// TODO
bool hermetik_mail_address_cmp_public_keys(const hermetik_mail_address *hma,
										   const hermetik_mail_address *hma2);

// TODO
void hermetik_mail_address_cmp(hermetik_mail_address_comparator *mac,
							   const hermetik_mail_address *hma,
							   const hermetik_mail_address *hma2);

//---------------------------- Helper Functions --------------------------------

void hermetik_hex_dump_str(const unsigned char *str,
						   size_t bytes,
						   size_t print_width);

char **hermetik_str_split(char *a_str,
				 		  const char a_delim);

//------------------------------------------------------------------------------
#endif
















