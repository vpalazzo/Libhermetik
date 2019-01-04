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

#include "hermetik.h"

//	The hermetik_init_keypair() function allocates memory to the
//	hermetik_keypair *kp. 
//
//	The calling function should check that the hermetik_keypair member
//	variables have been successfully initialized; e.g.
//
//		________________________________________________________
//
//		hermetik_init_keypair(my_keypair);
//
//		if (!my_keypair->public_key || !my_keypair->private_key)
//		{
//			fprintf(stderr, "Could not initialize keypair!\n");
//			goto clean_up;
//		}
//		________________________________________________________
//
void hermetik_init_keypair(hermetik_keypair *kp)
{
	// Check for null pointer
	if (!kp)
	{
		return;
	}

	// Allocate memory for the keypair members
	kp->public_key = calloc(1, HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES);
	kp->private_key = calloc(1, HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES);

	// Check that the previous memory allocations succeded
	if (!kp->public_key || !kp->private_key)
	{
		// One of the previous memory allocation attempts failed,
		// clean-up memory.
		hermetik_free_keypair(kp);
		return;
	}
}

//	The hermetik_init_keypair_with_keypair() function initializes the
//	hermetik_keypair *dst_kp and copies the keypair data pointed to by
//	*src_kp to *dst_kp.
//
//	The calling function should check that the hermetik_keypair member
//	variables have been successfully initialized - and the source keypair
//	data successfully copied; e.g.
//		_________________________________________________________
//		hermetik_init_keypair_with_keypair(my_keypair, other_kp);
//
//		if (!my_keypair->public_key 	||
//			!my_keypair->private_key	||
//			!hermetik_keypair_compare(my_keypair, other_kp))
//		{
//			fprintf(stderr, "Could not initialize keypair!\n");
//			goto clean_up;
//		}
//		_________________________________________________________
//
//	A more verbose 'if' statement could also be written like so:
//		_________________________________________________________
//		hermetik_init_keypair_with_keypair(my_keypair, other_kp);
//
//		if (!my_keypair->public_key 	||
//			!my_keypair->private_key	||
//			hermetik_keypair_compare(my_keypair, other_kp) !=
//				HERMETIK_KEYPAIR_COMPARE_IDENTICAL)
//		{
//			fprintf(stderr, "Could not initialize keypair!\n");
//			goto clean_up;
//		}
//		_________________________________________________________
//
//	An even more robust analysis:
//		_________________________________________________________
//		hermetik_init_keypair_with_keypair(my_keypair, other_kp);
//
//		if (!my_keypair->public_key 	||
//			!my_keypair->private_key)
//		{
//			fprintf(stderr, "Could not initialize keypair!\n");
//			goto clean_up;
//		}
//
//		if (!hermetik_keypair_compare(my_keypair, other_kp))
//		{
//			fprintf(stderr, "The keypair data wasn't copied correctly\n");
//			goto clean_up;
//		}
//		_________________________________________________________
//
//	If you decide to start hacking libhermetik, the more robust (last) analysis
//	method is preferred. The reason for this is that there may be a bug
//	introduced into either the hermetik_init_keypair() or
//	hermetik_keypair_copy() function(s). By analyzing the result of a call to
//	hermetik_init_keypair_with_keypair() in two steps, we can debug a potential
//	issue much quicker; as we can narrow down the source of the error in
//	less time.
//
void hermetik_init_keypair_with_keypair(hermetik_keypair *dst_kp,
										const hermetik_keypair *src_kp)
{
	// Check for null pointers
	if (!dst_kp 			||
		!src_kp 			||
		!src_kp->public_key ||
		!src_kp->private_key)
	{
		return;
	}

	// Initialize the destination keypair
	hermetik_init_keypair(dst_kp);

	// Copy the source keypair to the destination keypair
	hermetik_keypair_copy(dst_kp, src_kp);
}

//	The hermetik_keypair_copy() function copies the keypair data pointed to by
//	*src_kp to the keypair *dst_kp.
//
//	The calling function should check to ensure that the keypair data was copied
//	correctly; see the hermetik_keypair_compare() function.
//
void hermetik_keypair_copy(hermetik_keypair *dst_kp,
						   const hermetik_keypair *src_kp)
{
	// Check for null pointers
	if (!dst_kp ||
		!dst_kp->public_key ||
		!dst_kp->private_key ||
		!src_kp ||
		!src_kp->public_key ||
		!src_kp->private_key)
	{
		return;
	}

	// Zero out the destination keypair, it may have
	// previously received data.
	hermetik_keypair_zero_out(dst_kp);

	// Copy the source keypair public-key
	memcpy(dst_kp->public_key, src_kp->public_key,
		   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES);

	// Copy the source keypair private-key
	memcpy(dst_kp->private_key, src_kp->private_key,
		   HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES);
}

//	The hermetik_keypair_zero_out() function will zero-out (wipe) the keypair
//	data pointed to by *kp.
//
void hermetik_keypair_zero_out(hermetik_keypair *kp)
{
	// Check for null pointers
	if (!kp 			||
		!kp->public_key ||
		!kp->private_key)
	{
		return;
	}

	// Zero-out the public-key
	memset(kp->public_key, 0, HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES);

	// Zero-out the private-key
	memset(kp->private_key, 0, HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES);
}

//	The hermetik_free_keypair() function will deallocate any memory assigned
//	to the keypair *kp; from a previous call to the hermetik_init_keypair()
//	function.
//
//	It is safe to call this function with an un-initialized hermetik_keypair.
//
void hermetik_free_keypair(hermetik_keypair *kp)
{
	// Check for a null pointer
	if (!kp)
	{
		return;
	}

	// Check if the keypair->public_key has been allocated memory
	if (kp->public_key)
	{
		// Free the previously allocated memory
		free(kp->public_key);
	}

	// Check if the keypair->private_key has been allocated memory
	if (kp->private_key)
	{
		// Free the previously allocated memory
		free(kp->private_key);
	}
}

//	The hermetik_keypair_generate_keys() function generates a new pair
//	of public and private keys for the keypair *kp.
//
//	It is safe to call this function with an un-initialized keypair.
//
//	This function returns true if the public and private keys are generated
//	successfully.
//
bool hermetik_keypair_generate_keys(hermetik_keypair *kp)
{
	// Check that the keypair has been initialized and memory has been
	// allocated.
	if (!kp || !kp->public_key || !kp->private_key)
	{
		return false;
	}

	// Attempt to generate a new public-key pair. A return value of
	// 0 from the function crypto_box_keypair() indicates successful
	// key generation.
	return (crypto_box_keypair(kp->public_key, kp->private_key) == 0);
}

//	The hermetik_keypair_public_key_to_hex() function converts the public-key
//	pointed to by *kp into hexadecimal and places the result in *hex.
//
void hermetik_keypair_public_key_to_hex(const hermetik_keypair *kp,
										char *hex)
{
	// Check for null pointers
	if (!kp || !kp->public_key || !hex)
	{
		return;
	}

	// Encode the keypair->public_key binary data as hexadecimal. 
	sodium_bin2hex(hex, HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES,
				   kp->public_key, HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES);
}

//	The hermetik_keypair_private_key_to_hex() function converts the private-key
//	in the keypair *kp to hexadecimal and places the result in *hex.
//
void hermetik_keypair_private_key_to_hex(const hermetik_keypair *kp,
										 char *hex)
{
	// Check for null pointers
	if (!kp || !kp->private_key || !hex)
	{
		return;
	}

	// Encode the keypair->private_key binary data as hexadecimal
	sodium_bin2hex(hex, HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES,
				   kp->private_key, HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES);
}

//	The hermetik_keypair_compare() function takes two keypairs, *kp and
//	*kp2, compares their public and private keys, and returns an integer
//	result code. The following values may be used to evaluate the result code
//	returned from this method:
//
//	As defined in hermetik.h:
//	____________________________________________________________
//
//		#define HERMETIK_KEYPAIR_COMPARE_IDENTICAL			(0)
//		#define HERMETIK_KEYPAIR_COMPARE_PUBLIC_KEY_DIFF	(1)
//		#define HERMETIK_KEYPAIR_COMPARE_PRIVATE_KEY_DIFF	(2)
//		#define HERMETIK_KEYPAIR_COMPARE_NO_MATCH			(3)
//		#define HERMETIK_KEYPAIR_COMPARE_ERROR				(-1)
//	____________________________________________________________
//
int hermetik_keypair_compare(const hermetik_keypair *kp,
							 const hermetik_keypair *kp2)
{
	bool public_key_match = false;
	bool private_key_match = false;

	// Check for null pointers
	if (!kp || !kp2 || 
		!kp->public_key || !kp2->public_key ||
		!kp->private_key || !kp2->private_key)
	{
		// Inform the caller that they have passed incomplete data to this
		// function.
		return HERMETIK_KEYPAIR_COMPARE_ERROR;
	}

	// Compare the memory contents of the public-keys of each keypair.
	// This is a byte for byte comparison. 
	if (memcmp(kp->public_key,
			   kp2->public_key,
			   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES) == 0)
	{
		public_key_match = true;
	}

	// Compare the memory contents of the private-keys of each keypair.
	// This is a byte for byte comparison.
	if (memcmp(kp->private_key,
					kp2->private_key,
					HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES) == 0)
	{
		private_key_match = true;
	}

	// Check the status of the prior comparison operations.
	if (!public_key_match && !private_key_match)
	{
		// Neither key matched
		return HERMETIK_KEYPAIR_COMPARE_NO_MATCH;
	}
	else if (!public_key_match)
	{
		// The public-keys of both keypairs differ.
		return HERMETIK_KEYPAIR_COMPARE_PUBLIC_KEY_DIFF;
	}
	else if (!private_key_match)
	{
		// The private-keys of both keypairs differ.
		return HERMETIK_KEYPAIR_COMPARE_PRIVATE_KEY_DIFF;
	}
	else
	{
		// The contents of each keypair are indentical.
		return HERMETIK_KEYPAIR_COMPARE_IDENTICAL;
	}
}

//	The hermetik_init_sqlite3_keypair() function initializes the
//	sqlite3_keypair *skp. The given keypair should be analyzed after
//	a call to this function to ensure that it completed successfully.
//
//	e.g:
//		______________________________________________________________
//
//		hermetik_init_sqlite3_keypair(my_kp);
//
//		if (!my_kp->kp->public_key ||
//			!my_kp->kp->private_key)
//		{
//			fprintf(stderr, "Could not initialize sqlite3_keypair\n");
//		}
//		______________________________________________________________
//
void hermetik_init_sqlite3_keypair(hermetik_sqlite3_keypair *skp)
{
	// Check for a null pointer
	if (!skp)
	{
		return;
	}

	// Set the db_id
	skp->db_id = 0;

	// Allocate memory to the hermetik_sqlite3_keypair->keypair member
	skp->kp = calloc(1, sizeof(hermetik_keypair));

	// Allocate memory to the hermetik_sqlite3_keypair->comment member
	skp->comment = calloc(1, HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES);

	// Check that the previous memory allocations succeded
	if (!skp->kp || !skp->comment)
	{
		// One of the previous memory allocations failed, clean-up memory.
		hermetik_free_sqlite3_keypair(skp);
		return;
	}

	// Initialize the hermetik_sqlite3_keypair->keypair member
	hermetik_init_keypair(skp->kp);

	// Check if the previous keypair initialization succeded
	if (!skp->kp->public_key || !skp->kp->private_key)
	{
		// The keypair initialization failed, clean-up memory.
		hermetik_free_sqlite3_keypair(skp);	
	}
}

//	The hermetik_init_sqlite3_keypair_with_keypair() function initializes the
//	sqlite3_keypair *skp, and copies the keypair data from *kp. 
//
//	The given keypair should be analyzed after a call to this function to ensure
//	that it completed successfully.
//
//	e.g:
//		______________________________________________________________
//
//		hermetik_init_sqlite3_keypair_with_keypair(my_kp, other_kp);
//
//		if (!my_kp->kp->public_key ||
//			!my_kp->kp->private_key)
//		{
//			fprintf(stderr, "Could not initialize sqlite3_keypair\n");
//		}
//
//		if (hermetik_keypair_compare(my_kp->kp, other_kp) !=
//			HERMETIK_KEYPAIR_COMPARE_IDENTICAL)
//		{
//			fprintf(stderr, "The keypair data was not copied correctly\n");
//		}
//		______________________________________________________________
//
void hermetik_init_sqlite3_keypair_with_keypair(hermetik_sqlite3_keypair *skp,
												const hermetik_keypair *kp)
{
	// Check for null pointers
	if (!skp || !kp || !kp->public_key || !kp->private_key)
	{
		return;
	}

	// Initialize the hermetik_sqlite3_keypair
	hermetik_init_sqlite3_keypair(skp);

	// Check that the previous initialization succeded
	if (!skp->kp || !skp->kp->public_key || !skp->kp->private_key)
	{
		// The previous initialization attempt failed, clean-up memory.
		hermetik_free_sqlite3_keypair(skp);
		return;
	}

	// Copy the memory contents of the keypair->public_key to the
	// hermetik_sqlite3_keypair->public_key.
	memcpy(skp->kp->public_key, kp->public_key, 
		   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES);

	// Copy the memory contents of the keypair->private_key to the
	// hermetik_sqlite3_keypair->privaye_key.
	memcpy(skp->kp->private_key, kp->private_key,
		   HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES);
}

//	The hermetik_free_sqlite3_keypair() function de-allocates any memory
//	assigned to the sqlite3_keypair *skp.
//
//	This function is safe to call with an un-initialized sqlite3_keypair.
//
void hermetik_free_sqlite3_keypair(hermetik_sqlite3_keypair *skp)
{
	// Check for a null pointer
	if (!skp)
	{
		return;
	}

	// Reset the db_id
	skp->db_id = 0;

	// Check if the hermetik_sqlite3_keypair->keypair member has been
	// allocated memory.
	if (skp->kp)
	{
		// Free any memory assigned to the keypair members
		hermetik_free_keypair(skp->kp);

		// Free the keypair member itself.
		free(skp->kp);
	}

	// Check if the hermetik_sqlite3_keypair->comment member has been
	// allocated memory.
	if (skp->comment)
	{
		// Free the memory assigned to the comment member.
		free(skp->comment);
	}
}

//	The hermetik_sqlite3_keypair_set_comment() function sets the comment
//	string for the given sqlite3_keypair *skp, to *cmnt, of length cmnt_length.
//
//	This function is safe to call with an un-initialized sqlite3_keypair.
//
bool hermetik_sqlite3_keypair_set_comment(hermetik_sqlite3_keypair *skp,
										  const char *cmnt,
										  size_t cmnt_len)
{
	// Check for null pointers
	if (!skp 		  ||
		!skp->comment ||
		!cmnt		  ||
		cmnt_len > HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES)
	{
		return false;
	}

	// Zero-out the sqlite3_keypair->comment, it may have previously
	// received data.
	memset(skp->comment, 0, HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES);

	// Copy the supplied string to the sqlite3_keypair->comment
	memcpy(skp->comment, cmnt, cmnt_len);
	return true;
}

//	The hermetik_create_sqlite3_keypair_table() function creates the
//	KEYPAIR table in the SQLite database specified by *db_path.
//
//	The KEYPAIR table is used to store hermetik_sqlite3_keypair types.
//
bool hermetik_create_sqlite3_keypair_table(const char *db_path)
{
	sqlite3 *db = NULL;
	char *err_msg = NULL;
	int rc = 0;
	bool success = false;

	// Check for a null pointer
	if (!db_path)
	{
		return false;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded. This could also
	// be written as 'rc != SQLITE_OK'; as SQLITE_OK is defined as (0) in
	// the sqlite.h file.
	if (rc)
	{
		goto clean_up;
	}
	else
	{
		// Execute the CREATE_KEYPAIR_TABLE_SQL_STATEMENT
		if (sqlite3_exec(db, CREATE_KEYPAIR_TABLE_SQL_STATEMENT,
						 NULL, NULL, &err_msg) != SQLITE_OK)
		{
			// The execution attempt failed
			goto clean_up;
		}

		// The execution of the SQL statement was successful
		success = true;
	}

// Clean-up any allocated memory
clean_up:
	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_drop_sqlite3_keypair_table() function drops the
//	KEYPAIR table in the SQLite database specified by *db_path.
//
//	The KEYPAIR table is used to store hermetik_sqlite3_keypair types.
//
bool hermetik_drop_sqlite3_keypair_table(const char *db_path)
{
	sqlite3 *db = NULL;
	char *err_msg = NULL;
	int rc = 0;
	bool success = false;

	// Check for null pointer
	if (!db_path)
	{
		return false;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		// The connection attempt failed
		goto clean_up;
	}
	else
	{
		// Execute the DROP_KEYPAIR_TABLE_SQL_STATEMENT
		if (sqlite3_exec(db, DROP_KEYPAIR_TABLE_SQL_STATEMENT,
						 NULL, NULL, &err_msg) != SQLITE_OK)
		{
			// The execution attempt failed
			goto clean_up;
		}

		// The execution attempt was successful
		success = true;
	}

// Clean-up any allocated memory
clean_up:
	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_get_sqlite3_keypair_by_id() function attempts to
//	retrieve the record identified by db_id, stored in the KEYPAIR table,
//	within the SQLite database located at *db_path. If a record is
//	successfully retrieved, its data is stored in the sqlite3_keypair *skp.
//
//	This function returns 'true' if a record is successfully retrieved. False
//	otherwise.
//
bool hermetik_get_sqlite3_keypair_by_id(const char *db_path,
										const unsigned int db_id,
										hermetik_sqlite3_keypair *skp)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char pub_key_hex[HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES] = {'\0'};
	char pri_key_hex[HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES] = {'\0'};

	// Check for null pointers
	if (!db_path 				||
		db_id == 0 				||
		!skp					||
		!skp->kp				||
		!skp->kp->public_key	||
		!skp->kp->private_key	||
		!skp->comment)
	{
		return false;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_KEYPAIR_RECORD_BY_ID_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "Could not prepare the SQL statement\n");
			fprintf(stderr, "SQLITE Error Message:\n\n%s\n\n",
					sqlite3_errmsg(db));
			goto clean_up;
		}

		// Bind the db_id to the first parameter in the SQL statement
		sqlite3_bind_int(statement, 1, db_id);

		// Execute the SQL statement and check if we have retrieved a row
		if (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the db_id to the sqlite3_keypair
			skp->db_id = sqlite3_column_int(statement, 0);

			// Copy the private key, in hexadecimal form, to the local
			// pri_key_hex buffer.
			memcpy(pri_key_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);

			// Copy the public key, in hexadecimal form, to the local
			// pub_key_hex buffer.
			memcpy(pub_key_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);

			// Copy the comment to the sqlite3_keypair
			memcpy(skp->comment, sqlite3_column_text(statement, 3),
				   HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES);

			// Convert the hexadecimal form of the private key into binary
			// and store the result in the sqlite3_keypair->keypair->private_key
			sodium_hex2bin(skp->kp->private_key,
						   HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES,
						   pri_key_hex,
						   strlen(pri_key_hex),
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the public key into binary
			// and store the result in the sqlite3_keypair->keypair->public_key
			sodium_hex2bin(skp->kp->public_key,
						   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES,
						   pub_key_hex,
						   strlen(pub_key_hex),
						   NULL, NULL, NULL);

			// We successfully retrieved and processed the record
			success = true;
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_get_all_sqlite3_keypairs() function fetches all of the
//	records in the KEYPAIR TABLE, iterates over them, and stores them in
//	the *sqlite3_keypair(s) within *skps.
//
//	If this function is called with any un-initialized *sqlite3_keypair(s)
//	within *skps the behaviour is un-defined.
//
//	This function does no bounds checking. If *skps does not contain sufficient
//	memory to store all of the records within the KEYPAIR table, behaviour is
//	un-defined; more than likely, a SEGFAULT will occur. This is an obvious
//	buffer-overflow, but, this function allows the caller to ensure that data
//	remains on the stack.
//
//	If you wish to make efficient use of this function. It is recommended that
//	you limit the amount of records stored in the KEYPAIR table to that which
//	your environment can allocate memory for.
//
//	e.g.
//		____________________________________________________________
//
//		hermetik_sqlite3_keypair *skps[MAX_SAFE_AMOUNT_OF_KEYPAIRS];
//		hermetik_sqlite3_keypair *(*skps_ref)[] = &skps;
//
//		for (i = 0; i < MAX_SAFE_AMOUNT_OF_KEYPAIRS; i++)
//		{
//			skps[i] = malloc(sizeof(hermetik_sqlite3_keypair));
//			hermetik_init_sqlite3_keypair(skps[i]);
//		}
//
//		hermetik_get_all_sqlite3_keypairs(DATABASE_FILE, skps_ref);
//		____________________________________________________________
//
//	See hermetik_get_all_sqlite3_keypairs_v2() for a dynamic, heap based
//	version.
//
unsigned int hermetik_get_all_sqlite3_keypairs(const char *db_path,
											hermetik_sqlite3_keypair *(*skps)[])
{
	unsigned int count = 0;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char pub_key_hex[HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES] = {'\0'};
	char pri_key_hex[HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES] = {'\0'};

	// Check for a null pointer
	if (!db_path)
	{
		return 0;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_ALL_KEYPAIR_RECORDS_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occured preparing the SQL statement:\n"\
							"%s\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Execute the SQL statement, if we retrieve a row - process it.
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the db_id to the sqlite3_keypair
			(*skps)[count]->db_id = sqlite3_column_int(statement, 0);

			// Copy the private-key, as hexadecimal, to the temporary buffer
			// pri_key_hex.
			memcpy(pri_key_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);

			// Copy the public-key, as hexadecimal, to the temporary buffer
			// pub_key_hex.
			memcpy(pub_key_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);

			// Copy the comment to the sqlite3_keypair
			memcpy((*skps)[count]->comment, sqlite3_column_text(statement, 3),
				   HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES);

			// Convert the hexadecimal form of the private-key into binary, and
			// store the result in the sqlite3_keypair's->keypair->private_key.
			sodium_hex2bin((*skps)[count]->kp->private_key,
						   HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES,
						   pri_key_hex,
						   strlen(pri_key_hex),
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the public-key into binary, and
			// store the result in the sqlite3_keypair's->keypair->public_key.
			sodium_hex2bin((*skps)[count]->kp->public_key,
						   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES,
						   pub_key_hex,
						   strlen(pub_key_hex),
						   NULL, NULL, NULL);

			// Increase the counter as we've successfully processed a row.
			count++;

			// Zero-out the temporary pri_key_hex buffer.
			memset(pri_key_hex, 0,
				   HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);

			// Zero-out the temporary pub_key_hex buffer.
			memset(pub_key_hex, 0,
				   HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);
		}
	}

clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return count;
}

//	The hermetik_get_sqlite3_keypair_count() function returns the total
//	amount of records in the KEYPAIR table in the SQLite database specified
//	by *db_path.
//
unsigned int hermetik_get_sqlite3_keypair_count(const char *db_path)
{
	unsigned int count = 0;

	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;

	// Check for null pointer
	if (!db_path)
	{
		return 0;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded.
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_KEYPAIR_RECORD_COUNT_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if  (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occurred preparing the SQL statement:"\
							"\n%s\n\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Iterate through each row returned
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Increase the counter
			count = sqlite3_column_int(statement, 0);
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return count;
}

//	The hermetik_save_sqlite3_keypair() function adds a
//	hermetik_sqlite3_keypair to the SQLite database specified by *db_path.
//
//	The KEYPAIR table should be created first via a call to
//	hermetik_create_sqlite3_keypair_table().
//
bool hermetik_save_sqlite3_keypair(const char *db_path,
								   const hermetik_sqlite3_keypair *skp)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char pub_key_hex[HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES] = { '\0' };
	char pri_key_hex[HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES] = { '\0' };

	// Check for null pointers
	if (!db_path 			  ||
		!skp	 			  ||
		!skp->comment 		  ||
		!skp->kp 			  ||
		!skp->kp->public_key  ||
		!skp->kp->private_key)
	{
		return false;
	}

	// Convert the public-key to hexadecimal and store the result in pub_key_hex
	hermetik_keypair_public_key_to_hex(skp->kp, pub_key_hex);

	// Convert the private-key to hexadecimal and store the result in
	// pri_key_hex
	hermetik_keypair_private_key_to_hex(skp->kp, pri_key_hex);

	// Check that the temporary buffers actually contain data
	if (!(strlen(pub_key_hex) > 0) || !(strlen(pri_key_hex) > 0))
	{
		return false;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, INSERT_KEYPAIR_RECORD_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check the result of the previous call
		if (rc != SQLITE_OK)
		{
			goto clean_up;
		}

		// Bind the private-key, as hexadecimal, to the first parameter in the
		// SQL statement.
		sqlite3_bind_text(statement,
						  1,
						  pri_key_hex,
						  HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES,
						  SQLITE_STATIC);

		// Bind the public-key, as hexadecimal, to the second parameter in the
		// SQL statement.
		sqlite3_bind_text(statement,
						  2,
						  pub_key_hex,
						  HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES,
						  SQLITE_STATIC);

		// Bind the comment to the third parameter in the SQL statement.
		sqlite3_bind_text(statement,
						  3,
						  skp->comment,
						  HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES,
						  SQLITE_STATIC);

		// Check if the record insertion succeded
		if ((rc = sqlite3_step(statement)) == SQLITE_DONE)
		{
			success = true;
		}
		else
		{
			fprintf(stderr, "\n\nReturn code: %d\n", rc);
			fprintf(stderr, "***SQLITE3 Error Message:\n\n%s\n\n***\n\n",
					sqlite3_errmsg(db));
		}

		goto clean_up;
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_delete_sqlite3_keypair_by_id() function deletes a record
//	in the KEYPAIR table identified by db_id in the database *db_path.
//
bool hermetik_delete_sqlite3_keypair_by_id(const char *db_path,
										  unsigned int db_id)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;

	// Check for null pointer
	if (!db_path || db_id == 0)
	{
		return false;
	}

	// Attempt to open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, DELETE_KEYPAIR_RECORD_BY_ID_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "Could not prepare sql statement: %s\n",
					sqlite3_errmsg(db));
			goto clean_up;
		}

		// Bind the db_id to the first parameter in the SQL statement
		sqlite3_bind_int(statement, 1, db_id);

		// Check if the SQL statement executed successfully
		if ((rc = sqlite3_step(statement)) != SQLITE_DONE)
		{
			fprintf(stderr, "\n\nReturn code: %d\n\n", rc);
			fprintf(stderr, "SQLITE3 Error Message:\n\n%s\n\n",
					sqlite3_errmsg(db));
			fprintf(stderr, "Could not delete keypair: %d\n", db_id);
			goto clean_up;
		}

		// The SQL statement executed successfully
		success = true;
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_init_block() function initializes a hermetik_block.
//
void hermetik_init_block(hermetik_block *b)
{
	if (!b)
	{
		return;
	}

	// Allocate memory
	b->data = calloc(1, HERMETIK_BLOCK_DATA_SIZE_BYTES);
	b->encrypted_data = calloc(1, HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);

	// Check if either memory allocation attempt failed
	if (!b->data || !b->encrypted_data)
	{
		// Cleanup memory
		hermetik_free_block(b);
		return;
	}
}

//	The hermetik_free_block() function de-allocates any memory assigned
//	to a hermetik_block.
//
//	This function is safe to call with an un-initialized hermetik_block.
//
void hermetik_free_block(hermetik_block *b)
{
	// Check for null pointer
	if (!b)
	{
		return;
	}

	// Check if allocated memory
	if (b->data)
	{
		free(b->data);
	}

	if (b->encrypted_data)
	{
		free(b->encrypted_data);
	}
}

//	The hermetik_block_encrypt_with_keypair() function encrypts the data
//	at b->data and places the result at b->encrypted_data.
//
//	This function is safe to call with an uninitialized block and/or keypair.
//
bool hermetik_block_encrypt_with_keypair(hermetik_block *b,
										 const hermetik_keypair *kp)
{
	int rc = 0;

	// Check for null pointers
	if (!b 					||
		!b->data 			||
		!b->encrypted_data 	||
		!kp 				||
		!kp->public_key		||	// Required for the encryption
		!kp->private_key)		// Not required, but check for consistency.
	{
		return false;
	}

	// Zero-out b->encrypted_data, it may have received garbage
	memset(b->encrypted_data, 0, HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);

	// Encrypt the data
	rc = crypto_box_seal(b->encrypted_data,
						 b->data,
						 HERMETIK_BLOCK_DATA_SIZE_BYTES,
						 kp->public_key);

	// Check if the encryption succeded
	return (rc == 0);
}

//	The hermetik_block_decrypt_with_keypair() function decrypts the data at
//	b->data and places the result at b->encrypted_data.
//
//	This function is safe to call with an uninitialized block and/or keypair.
//
bool hermetik_block_decrypt_with_keypair(hermetik_block *b,
										 const hermetik_keypair *kp)
{
	int rc = 0;

	// Check for null pointers
	if (!b ||
		!b->data ||
		!b->encrypted_data ||
		!kp	||
		!kp->public_key	||
		!kp->private_key)
	{
		return false;
	}

	// Zero-out b->data, it may have received garbage
	memset(b->data, 0, HERMETIK_BLOCK_DATA_SIZE_BYTES);

	// Decrypt the data
	rc = crypto_box_seal_open(b->data,
							  b->encrypted_data,
							  HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES,
							  kp->public_key,
							  kp->private_key);

	// Check if the decryption was successful
	return (rc == 0);
}

//	The hermetik_block_zero_out() function writes over b->data and
//	b->encrypted_data with zeros.
//
void hermetik_block_zero_out(hermetik_block *b)
{
	// Check for null pointers
	if (!b || !b->data || !b->encrypted_data)
	{
		return;
	}

	// Zero-out b->data and b->encrypted_data
	memset(b->data, 0, HERMETIK_BLOCK_DATA_SIZE_BYTES);
	memset(b->encrypted_data, 0, HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);
}

//	The hermetik_block_set_data() function writes dlen bytes starting
//	from *d to *b->data. 
//
void hermetik_block_set_data(hermetik_block *b,
							 const unsigned char *d,
							 size_t dlen)
{
	// Check for null pointers
	if (!b 					||
		!b->data 			||
		!b->encrypted_data 	||
		!d 					||
		dlen > HERMETIK_BLOCK_DATA_SIZE_BYTES)	// Check for overflow
	{
		return;
	}

	// Zero-out b->data, it may have received garbage
	memset(b->data, 0, HERMETIK_BLOCK_DATA_SIZE_BYTES);

	// Copy dlen bytes from d to b->data
	memcpy(b->data, d, dlen);
}

//	The hermetik_block_set_encrypted_data() function writes dlen bytes from
//	*d to b->encrypted_data.
//
void hermetik_block_set_encrypted_data(hermetik_block *b,
									   const unsigned char *d,
									   size_t dlen)
{
	// Check for null pointers
	if (!b					||
		!b->data			||
		!b->encrypted_data	||
		!d					||
		dlen > HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES)	// Check for overflow
	{
		return;
	}

	// Zero-out b->encrypted_data, it may have received garbage
	memset(b->encrypted_data, 0, HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);

	// Write dlen bytes from d to b->encrypted.
	memcpy(b->encrypted_data, d, dlen);
}

//	The hermetik_block_data_to_hex() function converts b->data to hexadecimal
//	and places the result in hex.
//
void hermetik_block_data_to_hex(const hermetik_block *b,
								char *hex)
{
	// Check for null pointers
	if (!b || !b->data || !hex)
	{
		return;
	}

	// Convert b->data to hexadecimal and place the result in hex
	sodium_bin2hex(hex, HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES,
				   b->data, HERMETIK_BLOCK_DATA_SIZE_BYTES);
}

//	The hermetik_block_encrypted_data_to_hex() function converts
//	b->encrypted_data to hexadecimal and places the result in hex.
//
void hermetik_block_encrypted_data_to_hex(const hermetik_block *b,
										  char *hex)
{
	// Check for null pointers
	if (!b || !b->encrypted_data || !hex)
	{
		return;
	}

	// Convert b->encrypted_data to hexadecimal and place the result in hex
	sodium_bin2hex(hex, HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES,
				   b->encrypted_data, HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);
}

//	The hermetik_block_compare() function compares two blocks and returns
//	a result code. The potential result codes are as follows:
//
//		As defined in hermetik.h
//			____________________________________________________
//
//			#define HERMETIK_BLOCK_COMPARE_IDENTICAL		(0)
//			#define HERMETIK_BLOCK_COMPARE_DATA_DIFF		(1)
//			#define HERMETIK_BLOCK_COMPARE_ENC_DATA_DIFF	(3)
//			#define HERMETIK_BLOCK_COMPARE_NO_MATCH			(4)
//			#define HERMETIK_BLOCK_COMPARE_ERROR			(-1)
//			____________________________________________________
//
int hermetik_block_compare(const hermetik_block *b,
						   const hermetik_block *b2)
{
	// Check for null pointers
	if (!b					||
		!b->data 			||
		!b->encrypted_data 	||
		!b2 				||
		!b2->data 			||
		!b2->encrypted_data)
	{
		return HERMETIK_BLOCK_COMPARE_ERROR;
	}

	if (!hermetik_block_compare_data(b, b2) &&
		!hermetik_block_compare_encrypted_data(b, b2))
	{
		return HERMETIK_BLOCK_COMPARE_NO_MATCH;
	}
	else if (!hermetik_block_compare_data(b, b2))
	{
		return HERMETIK_BLOCK_COMPARE_DATA_DIFF;
	}
	else if (!hermetik_block_compare_encrypted_data(b, b2))
	{
		return HERMETIK_BLOCK_COMPARE_ENC_DATA_DIFF;
	}
	else
	{
		return HERMETIK_BLOCK_COMPARE_IDENTICAL;
	}
}

//	The hermetik_block_compare_data() function compares b->data and
//	b2->data. It returns true if they are identical, false otherwise.	
//
bool hermetik_block_compare_data(const hermetik_block *b,
								 const hermetik_block *b2)
{
	// Check for null pointers
	if (!b 			||
		!b->data 	||
		!b2 		||
		!b2->data)
	{
		return false;
	}

	// Compare b->data and b2->data byte for byte. Return true only on an
	// exact match.
	return (memcmp(b->data, b2->data, HERMETIK_BLOCK_DATA_SIZE_BYTES) == 0);
}

//	The hermetik_block_compare_encrypted_data() function compares
//	b->encrypted_data and b2->encrypted data. It returns true only if they
//	are an exact match.
//
bool hermetik_block_compare_encrypted_data(const hermetik_block *b,
										   const hermetik_block *b2)
{
	// Check for null pointers
	if (!b 					||
		!b->encrypted_data 	||
		!b2 				||
		!b2->encrypted_data)
	{
		return false;
	}

	// Compare b->encrypted_data and b2->encrypted_data. Return true only if
	// they match byte for byte.
	return (memcmp(b->encrypted_data, b2->encrypted_data,
				   HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES) == 0);
}

//	The hermetik_block_copy() function makes a copy of a block.
//
void hermetik_block_copy(hermetik_block *b, const hermetik_block *src_b)
{
	// Copy the data from src_b to b
	hermetik_block_copy_data(b, src_b);

	// Copy the encrypted data from src_b to b
	hermetik_block_copy_encrypted_data(b, src_b);
}

//	The hermetik_block_copy_data() function copies scr_b->data to b->data.
//
void hermetik_block_copy_data(hermetik_block *b, const hermetik_block *src_b)
{
	// Check for null pointers
	if (!b 			||
		!b->data 	||
		!src_b 		||
		!src_b->data)
	{
		return;
	}

	// Copy src_b->data to b->data, byte for byte
	memcpy(b->data, src_b->data, HERMETIK_BLOCK_DATA_SIZE_BYTES);
}

//	The hermetik_block_copy_encrypted_data() function copies 
//	src_b->encrypted_data to b->encrypted_data.
//
void hermetik_block_copy_encrypted_data(hermetik_block *b,
										const hermetik_block *src_b)
{
	// Check for null pointers
	if (!b ||
		!b->encrypted_data ||
		!src_b ||
		!src_b->encrypted_data)
	{
		return;
	}

	// Copy src_b->encrypted_data to b->encrypted_data, byte for byte
	memcpy(b->encrypted_data, src_b->encrypted_data,
		   HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);
}

//	The hermetik_init_note() function initializes the note *hn
//
void hermetik_init_note(hermetik_note *hn)
{
	size_t i = 0;

	// Check for null pointer
	if (!hn)
	{
		return;
	}

	// Allocate memory to hn->title
	hn->title = calloc(1, sizeof(hermetik_block));

	// Check if the previous memory allocate attempt succeded
	if (!hn->title)
	{
		return;
	}

	// Initialize the note
	hermetik_init_block(hn->title);

	// Iterate through, and initialize each block composing the note 'body'
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Allocate memory to the block (hn->body[block_idx])
		hn->body[i] = calloc(1, sizeof(hermetik_block));

		// Check if the memory allocate attempt succeded
		if (!hn->body[i])
		{
			// The memory allocation attempt failed, cleanup memory
			hermetik_free_note(hn);
			return;
		}

		// Initialize the note 'body' block (hn->body[block_idx])
		hermetik_init_block(hn->body[i]);
	}
}

//	The hermetik_free_note() function de-allocates any memory assigned to the
//	note *hn.
//
void hermetik_free_note(hermetik_note *hn)
{
	size_t i = 0;

	// Check for null pointers
	if (!hn)
	{
		return;
	}

	// Check if memory has been allocated to hn->title
	if (hn->title)
	{
		// Free the block (hn->title)
		hermetik_free_block(hn->title);

		// Free hn->title
		free(hn->title);
	}

	// Iterate through each block composing the note 'body' and de-allocate
	// any allocated memory.
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Check for null pointer; defensive programming
		if (hn->body[i])
		{
			// Free the block (hn->body[block_idx])
			hermetik_free_block(hn->body[i]);

			// Free hn->body[block_idx]
			free(hn->body[i]);
		}
	}
}

//	The hermetik_note_set_title() function copies dlen bytes, starting from
//	d, to hn->title->data
//
void hermetik_note_set_title(hermetik_note *hn,
							 const unsigned char *d,
							 size_t dlen)
{
	// Check for null pointers
	if (!hn 						||
		!hn->title 					||
		!hn->title->data 			||
		!hn->title->encrypted_data	||
		dlen > HERMETIK_NOTE_TITLE_SIZE_BYTES)	// Check for overflow
	{
		return;
	}

	// Copy dlen bytes, starting from d, to hn->title->data
	hermetik_block_set_data(hn->title, d, dlen);
}

//	The hermetik_note_set_encrypted_title() function copies dlen bytes, starting
//	from d, to hn->title->encrypted_data.
//
void hermetik_note_set_encrypted_title(hermetik_note *hn,
									   const unsigned char *d,
									   size_t dlen)
{
	// Check for null pointers
	if (!hn ||
		!hn->title ||
		!hn->title->encrypted_data ||
		dlen > HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES)	// Check for overflow
	{
		return;
	}

	// Copy dlen bytes, starting from d, to hn->title->encrypted_data
	hermetik_block_set_encrypted_data(hn->title, d, dlen);
}

//	The hermetik_note_set_body() function copies dlen bytes, starting from d,
//	to hn->body.
void hermetik_note_set_body(hermetik_note *hn,
							const unsigned char *d,
							size_t dlen)
{
	const unsigned char *marker = d;
	size_t i = 0;
    size_t whole_blocks_required = 0;
    bool partial_block_required = false;

	// Check for null pointers
	if (!hn 			||
		!hn->title 		||
		!hn->body[0] 	||
		!d 				||
		dlen > HERMETIK_NOTE_BODY_SIZE_BYTES ||
        dlen == 0)
	{
		return;
	}
    
    if (dlen == HERMETIK_BLOCK_DATA_SIZE_BYTES)
    {
        whole_blocks_required = 1;
    }
    else if (dlen < HERMETIK_BLOCK_DATA_SIZE_BYTES)
    {
        partial_block_required = true;
    }
    else
    {
        whole_blocks_required = (dlen / HERMETIK_BLOCK_DATA_SIZE_BYTES);
        partial_block_required = (dlen % HERMETIK_BLOCK_DATA_SIZE_BYTES > 0);
    }

	// Sanity Check - ensure that each block has been initialized correctly.
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		if (!hn->body[i])
		{
			return;
		}
	}

	// Iterate through each whole block required
	for (i = 0; i < whole_blocks_required; i++)
	{
		// Set the block data
		hermetik_block_set_data(hn->body[i], marker,
								HERMETIK_BLOCK_DATA_SIZE_BYTES);

		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_DATA_SIZE_BYTES;
	}

	// Check if a partial/ extra block is required
	if (partial_block_required)
	{
		// Set the block data
		hermetik_block_set_data(hn->body[i], marker, 
								(dlen % HERMETIK_BLOCK_DATA_SIZE_BYTES));
	}
}

//void hermetik_note_set_body(hermetik_note *hn,
//							const unsigned char *d,
//							size_t dlen)
//{
//	const unsigned char *marker = d;
//	size_t i = 0;
//	size_t whole_blocks_required = (dlen / HERMETIK_BLOCK_DATA_SIZE_BYTES);
//	bool partial_block_required = (dlen % HERMETIK_BLOCK_DATA_SIZE_BYTES > 0);
//
//	// Check for null pointers
//	if (!hn 			||
//		!hn->title 		||
//		!hn->body[0] 	||
//		!d 				||
//		dlen > HERMETIK_NOTE_BODY_SIZE_BYTES)	// Check for overflow
//	{
//		return;
//	}
//
//	// Sanity Check - ensure that each block has been initialized correctly.
//	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
//	{
//		if (!hn->body[i])
//		{
//			return;
//		}
//	}
//
//	// Iterate through each whole block required
//	for (i = 0; i < whole_blocks_required; i++)
//	{
//		// Set the block data
//		hermetik_block_set_data(hn->body[i], marker,
//								HERMETIK_BLOCK_DATA_SIZE_BYTES);
//
//		// Move the marker forward through the buffer
//		marker += HERMETIK_BLOCK_DATA_SIZE_BYTES;
//	}
//
//	// Check if a partial/ extra block is required
//	if (partial_block_required)
//	{
//		// Move the marker forward through the buffer
//		marker += HERMETIK_BLOCK_DATA_SIZE_BYTES;
//
//		// Set the block data
//		hermetik_block_set_data(hn->body[i], marker, 
//								(dlen % HERMETIK_BLOCK_DATA_SIZE_BYTES));
//	}
//}

//	The hermetik_note_set_encrypted_body() function copies dlen bytes,
//	starting from d, to hn->body (encrypted).
//
void hermetik_note_set_encrypted_body(hermetik_note *hn,
									  const unsigned char *d,
									  size_t dlen)
{
	const unsigned char *marker = d;
	size_t i = 0;
	size_t whole_blocks_required = (dlen / HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);
	bool partial_block_required = (dlen % HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES >
									0);

	// Check for null pointers
	if (!hn ||
		!hn->title ||
		!d ||
		dlen > HERMETIK_NOTE_ENC_BODY_SIZE_BYTES)	// Check for overflow
	{
		return;
	}

	// Sanity Check - ensure that each block has been initialized correctly.
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		if (!hn->body[i])
		{
			return;
		}
	}

	// Iterate through each whole block required
	for (i = 0; i < whole_blocks_required; i++)
	{
		// Set the encrypted data
		hermetik_block_set_encrypted_data(hn->body[i], marker,
										  HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);

		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES;
	}

	// Check if an extra block is required
	if (partial_block_required)
	{
		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES;

		// Set the encrypted data
		hermetik_block_set_encrypted_data(hn->body[i], marker,
										  (dlen % 
										   HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES));
	}
}

//	The hermetik_note_encrypt_title_with_keypair() function encrypts the
//	note->title with the keypair kp.
//
bool hermetik_note_encrypt_title_with_keypair(hermetik_note *hn,
											  const hermetik_keypair *kp)
{
	// Check for null pointers
	if (!hn 			||
		!hn->title 		||
		!kp 			||
		!kp->public_key ||
		!kp->private_key)
	{
		return false;
	}

	// Encrypt the block with the given keypair
	return hermetik_block_encrypt_with_keypair(hn->title, kp);
}

//	The hermetik_note_encrypt_body_with_keypair() function encrypts the
//	note->body with the keypair kp.
//
bool hermetik_note_encrypt_body_with_keypair(hermetik_note *hn,
											 const hermetik_keypair *kp)
{
	size_t i = 0;
	bool success = false;

	// Check for null pointers
	if (!hn				||
		!hn->body[0] 	||
		!kp				||
		!kp->public_key ||
		!kp->private_key)
	{
		return false;
	}

	// Iterate through each block composing the note 'body'
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Encrypt the block with the given keypair
		success = hermetik_block_encrypt_with_keypair(hn->body[i], kp);

		// Check if the encryption was successful
		if (!success)
		{
			// Cease processing immediately if encryption fails
			break;
		}
	}

	return success;
}

//	The hermetik_note_encrypt_with_keypair() function encrypts both the note
//	title and body with the given keypair.
//
bool hermetik_note_encrypt_with_keypair(hermetik_note *hn,
										const hermetik_keypair *kp)
{
	// Encrypt the note title and body with the given keypair
	return (hermetik_note_encrypt_title_with_keypair(hn, kp) &&
			hermetik_note_encrypt_body_with_keypair(hn, kp));
}

//	The hermetik_note_decrypt_title_with_keypair() function decrypts
//	the note->title using the given keypair.
//
bool hermetik_note_decrypt_title_with_keypair(hermetik_note *hn,
											  const hermetik_keypair *kp)
{
	// Check for null pointers
	if (!hn 			||
		!hn->title 		||
		!kp 			||
		!kp->public_key ||
		!kp->private_key)
	{
		return false;
	}

	// Decrypt the note->title
	return hermetik_block_decrypt_with_keypair(hn->title, kp);
}

//	The hermetik_note_decrypt_body_with_keypair() function decrypts the
//	note->body using the given keypair.
//
bool hermetik_note_decrypt_body_with_keypair(hermetik_note *hn,
											 const hermetik_keypair *kp)
{
	size_t i = 0;
	bool success = false;

	// Check for null pointers
	if (!hn ||
		!hn->body[0] ||
		!kp	||
		!kp->public_key ||
		!kp->private_key)
	{
		return false;
	}

	// Iterate through each block composing the note 'body'
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Decrypt the block
		success = hermetik_block_decrypt_with_keypair(hn->body[i], kp);

		// Check if the decryption was successful
		if (!success)
		{
			// Cease processing immediately if decryption fails
			break;
		}
	}

	return success;
}

//	The hermetik_note_decrypt_with_keypair() function decrypts both the
//	note->title and note->body with the given keypair.
//
bool hermetik_note_decrypt_with_keypair(hermetik_note *hn,
										const hermetik_keypair *kp)
{
	// Decrypt the note->title and note->body
	return (hermetik_note_decrypt_title_with_keypair(hn, kp) &&
			hermetik_note_decrypt_body_with_keypair(hn, kp));
}

//	The hermetik_note_encrypted_title_to_hex() function converts the
//	encrypted note->title to hexadecimal and places the result at *hex.
//
void hermetik_note_encrypted_title_to_hex(const hermetik_note *hn,
										  char *hex)
{
	// Check for null pointers
	if (!hn 						||
		!hn->title					||
		!hn->title->encrypted_data	||
		!hex)
	{
		return;
	}

	// Convert the encrypted block (note->title) to hexadecimal and
	// store the result in hex.
	hermetik_block_encrypted_data_to_hex(hn->title, hex);
}

//	The hermetik_note_title_to_hex() function converts the note->title to
//	hexadecimal and stores the result in *hex.
//
void hermetik_note_title_to_hex(const hermetik_note *hn,
								char *hex)
{
	// Check for null pointers
	if (!hn 		||
		!hn->title 	||
		!hn->title->data)
	{
		return;
	}

	// Convert the note->title->data to hexadecimal and store the result in hex.
	sodium_bin2hex(hex, HERMETIK_NOTE_TITLE_AS_HEX_SIZE_BYTES,
				   hn->title->data, HERMETIK_NOTE_TITLE_SIZE_BYTES);
}

//	The hermetik_note_body_to_hex() function converts the note->body to
//	hexadecimal and stores the result in *hex.
//
void hermetik_note_body_to_hex(const hermetik_note *hn,
							   char *hex)
{
	size_t i = 0;
	char tmp[HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES] = { '\0' };
	char *marker = hex;

	// Check for null pointers
	if (!hn || !hn->body[0] || !hex)
	{
		return;
	}

	// Iterate through each block composing the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Convert the block->data to hexadecimal and store the result in tmp
		hermetik_block_data_to_hex(hn->body[i], tmp);

		// Copy the hexadecimal block data from tmp to marker
		memcpy(marker, tmp, HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES);

		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES - 1;

		// Zero-out the buffer
		memset(tmp, 0, HERMETIK_BLOCK_DATA_AS_HEX_SIZE_BYTES);
	}
}

//	The hermetik_note_encrypted_body_to_hex() function converts the
//	encrypted form of the note->body to hexadecimal and stores the result
//	at *hex.
//
void hermetik_note_encrypted_body_to_hex(const hermetik_note *hn,
										 char *hex)
{
	size_t i = 0;
	char tmp[HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES] = { '\0' };
	char *marker = hex;

	// Check for null pointers
	if (!hn || !hn->body[0] || !hex)
	{
		return;
	}

	// Iterate through each block composing the encrypted note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Convert the encrypted block data to hexadecimal and place the
		// result in tmp.
		hermetik_block_encrypted_data_to_hex(hn->body[i], tmp);

		// Copy the encrypted block data from tmp to marker
		memcpy(marker, tmp, HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES);

		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES - 1;

		// Zero-out the temporary buffer
		memset(tmp, 0, HERMETIK_BLOCK_ENC_DATA_AS_HEX_SIZE_BYTES);
	}
}

//	The hermetik_note_zero_out_title() function zeros-out (wipes)
//	the note->title.
//
void hermetik_note_zero_out_title(hermetik_note *hn)
{
	// Check for null pointers
	if (!hn || !hn->title)
	{
		return;
	}

	// Zero-out the note->title
	hermetik_block_zero_out(hn->title);
}

//	The hermetik_note_zero_out_body() function zeros-out (wipes)
//	the note->body.
//
void hermetik_note_zero_out_body(hermetik_note *hn)
{
	size_t i = 0;

	// Check for null pointers
	if (!hn ||
		!hn->body[0])
	{
		return;
	}

	// Iterate through each block composing the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Check for null pointer
		if (!hn->body[i])
		{
			// We'll continue attempting to zero-out the remaining blocks.
			continue;
		}

		// Zero out the block
		hermetik_block_zero_out(hn->body[i]);
	}
}

//	The hermetik_note_copy_title() function copies the note->title to
//	*dst.
//
//	This function assumes that *dst can store HERMETIK_NOTE_TITLE_SIZE_BYTES.
//
void hermetik_note_copy_title(const hermetik_note *hn,
							  unsigned char *dst)
{
	// Check for null pointers
	if (!hn 				||
		!hn->title			||
		!hn->title->data	||
		!dst)
	{
		return;
	}

	// Copy the note->title->data to dst
	memcpy(dst, hn->title->data, HERMETIK_NOTE_TITLE_SIZE_BYTES);
}

//	The hermetik_note_copy_encrypted_title() function copies the note->title,
//	in encrypted binary form, to *dst.
//
//	This function assumes that *dst can store
//	HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES.
//
void hermetik_note_copy_encrypted_title(const hermetik_note *hn,
										unsigned char *dst)
{
	// Check for null pointers
	if (!hn							||
		!hn->title					||
		!hn->title->encrypted_data 	||
		!dst)
	{
		return;
	}

	// Copy the encrypted note->title binary data to *dst
	memcpy(dst, hn->title->encrypted_data, HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES);
}

//	The hermetik_copy_encrypted_body() function copies the note->body. in
//	encrypted binary form, to *dst.
//
//	This function assumes that *dst can store HERMETIK_NOTE_ENC_BODY_SIZE_BYTES.
//
void hermetik_note_copy_encrypted_body(const hermetik_note *hn,
									   unsigned char *dst)
{
	size_t i = 0;
	unsigned char *marker = dst;

	// Check for null pointers
	if (!hn				||
		!hn->body[0]	||
		!dst)
	{
		return;
	}

	// Iterate through each block composing the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Copy the encrypted block data to the *dst buffer
		memcpy(marker, hn->body[i]->encrypted_data,
			   HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES);

		// Move the marker forward along the buffer
		marker += HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES;
	}
}

//	The hermetik_note_copy_body() function copies the note->body to
//	*dst.
//
void hermetik_note_copy_body(const hermetik_note *hn,
							 unsigned char *dst)
{
	size_t i = 0;
	unsigned char *marker = dst;

	// Check for null pointers
	if (!hn				||
		!hn->body[0]	||
		!dst)
	{
		return;
	}

	// Interate through each block in the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Copy the note->body[block_idx]->data to *dst
		memcpy(marker, hn->body[i]->data, HERMETIK_BLOCK_DATA_SIZE_BYTES);

		// Move the marker forward through the buffer
		marker += HERMETIK_BLOCK_DATA_SIZE_BYTES;
	}
}

//	The hermetik_note_hex_dump_body() function will print a hex dump of the
//	given note->body to the screen, block by block.
//
void hermetik_note_hex_dump_body(const hermetik_note *hn)
{
	size_t i = 0;

	// Check for null pointers
	if (!hn || !hn->body[0])
	{
		return;
	}

	// Iterate through each block in the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Print a heading
		printf("hermetik_note->body[%zu]->data (hex)\n", i);

		// Execute hex dump
		hermetik_hex_dump_str(hn->body[i]->data, HERMETIK_BLOCK_DATA_SIZE_BYTES,
							  10);
	}
}

//	The hermetik_note_hex_dump_encrypted_body() function will print a hex dump
//	of the given note->body (in encrypted form), block by block.
//
void hermetik_note_hex_dump_encrypted_body(const hermetik_note *hn)
{
	size_t i = 0;

	// Check for null pointers
	if (!hn || !hn->body[0])
	{
		return;
	}

	// Iterate through each block in the note->body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Print a heading
		printf("hermetik_note->body[%zu]->encrypted_data (hex)\n", i);

		// Execute hex dump
		hermetik_hex_dump_str(hn->body[i]->encrypted_data,
							  HERMETIK_BLOCK_ENC_DATA_SIZE_BYTES,
							  10);
	}
}

//	The hermetik_note_zero_out() function zeros-out (wipes) the
//	given note->title and note->body.
//
void hermetik_note_zero_out(hermetik_note *hn)
{
	// Check for null pointers
	if (!hn 						||
		!hn->title 					||
		!hn->title->data			||
		!hn->title->encrypted_data	||
		!hn->body[0])
	{
		return;
	}

	// Zero-out the note->title
	hermetik_note_zero_out_title(hn);

	// Zero-out the note->body
	hermetik_note_zero_out_body(hn);
}

//	The hermetik_hex_dump_str() function prints the given number
//	of bytes, starting at *str, as hexadecimal values. The third parameter,
//	print_width, sets the number of bytes printed per line.
//
void hermetik_hex_dump_str(const unsigned char *str,
						   size_t bytes,
						   size_t print_width)
{
	// Check for null pointers
	if (!str || bytes < 1 || print_width < 1)
	{
		return;
	}

	size_t i;

	// Iterate through each byte in *str
    for (i = 0; i < bytes; i++)
    {
		// If we've printed print_width bytes to the screen,
		// print a newline character.
        if (i != 0 && (i % print_width) == 0)
        {
            printf("\n");
        }
            
		if (str[i] == 0x00)
		{
			printf("00 ");
		}
		else if (str[i] <= 0x0f)
		{
			printf("0%x ", str[i]);
		}
		else
		{
			printf("%x ", str[i]);
		}
	}

	printf("\n\n");
}

//	The hermetik_str_split() function separates tokens in a string
//	delimited by a_delim.
//
char** hermetik_str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;
    
    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }
    
    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);
    
    /* Add space for terminating null string so caller
     knows where the list of returned strings ends. */
    count++;

    result = calloc(count, sizeof(char*));
    
    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);
        
        while (token)
        {
            if (idx < count)
            {
                *(result + idx++) = strdup(token);
                token = strtok(0, delim);
            }
        }
        if (idx == (count - 1))
        {
            *(result + idx) = 0;
        }
    }
    
    return result;
}


//	The hermetik_delete_sqlite3_keypair() function deletes the given
//	keypair from the KEYPAIR table in the database specified by *db_path.
//
bool hermetik_delete_sqlite3_keypair(const char *db_path,
									 const hermetik_sqlite3_keypair *skp)
{
	// Check for null pointers
	if (!db_path || !skp)
	{
		return false;
	}

	// Delete the keypair
	return hermetik_delete_sqlite3_keypair_by_id(db_path, skp->db_id);
}

//	The hermetik_init_sqlite3_note() function initializes the given
//	sqlite3_note.
//
void hermetik_init_sqlite3_note(hermetik_sqlite3_note *sn)
{
	// Check for null pointer
	if (!sn)
	{
		return;
	}

	// Set the db_id to 0
	sn->db_id = 0;

	// Allocate memory to sqlite3_note->hermetik_note
	sn->hn = calloc(1, sizeof(hermetik_note));

	// Check if the memory allocation succeded
	if (!sn->hn)
	{
		// The memory allocation attempt failed
		return;
	}

	// Initialize the sqlite3_note->hermetik_note
	hermetik_init_note(sn->hn);
}

//	The hermetik_free_sqlite3_note() function de-allocates any memory allocated
//	to the given sqlite3_note via a call to the hermetik_init_sqlite3_note()
//	function.
//
void hermetik_free_sqlite3_note(hermetik_sqlite3_note *sn)
{
	// Check for null pointers
	if (!sn)
	{
		return;
	}

	// Check if sqlite3_note->hermetik_note has been initialized
	if (sn->hn)
	{
		// Free any memory allocated to the note
		hermetik_free_note(sn->hn);

		// Free the note
		free(sn->hn);
	}
}

//	The hermetik_create_sqlite3_note_table() function creates the NOTE
//	table in the SQLite database identified by *db_path.
//
bool hermetik_create_sqlite3_note_table(const char *db_path)
{
	sqlite3 *db = NULL;
	char *err_msg = NULL;
	int rc = 0;

	bool success = false;

	// Check for null pointer
	if (!db_path)
	{
		return false;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
	}
	else
	{
		// Execute the SQL statement
		if (sqlite3_exec(db, CREATE_NOTE_TABLE_SQL_STATEMENT,
						 NULL, NULL, &err_msg) != SQLITE_OK)
		{
			fprintf(stderr, "Could not create NOTE table!:\n\n%s\n",
					err_msg);
			goto clean_up;
		}

		// SQL statement executed successfully
		success = true;
	}

// Cleanup memory
clean_up:
	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_drop_sqlite3_note_table() function drops the NOTE table
//	in the SQLite database identified by *db_path.
//
bool hermetik_drop_sqlite3_note_table(const char *db_path)
{
	sqlite3 *db = NULL;
	char *err_msg = NULL;
	int rc = 0;
	bool success = false;

	// Check for null pointer
	if (!db_path)
	{
		return false;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the connection attempt was successful
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
	}
	else
	{
		// Execute the SQL statement
		if (sqlite3_exec(db, DROP_NOTE_TABLE_SQL_STATEMENT,
						NULL, NULL, &err_msg) != SQLITE_OK)
		{
			fprintf(stderr, "Could not drop NOTE table!:\n\n%s\n", err_msg);
			goto clean_up;
		}

		// The SQL statement executed successfully
		success = true;
	}

// Cleanup memory
clean_up:
	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_get_sqlite3_note_by_id() function retrieves the record
//	from the NOTE table identified by db_id, in the SQLite database *db_path,
//	and copies the retrieved data to the supplied note.
//
bool hermetik_get_sqlite3_note_by_id(const char *db_path,
									 const unsigned int db_id,
									 hermetik_sqlite3_note *sn)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	unsigned char *enc_title_bin = NULL;
	unsigned char *enc_body_bin = NULL;

	// Check for null pointers
	if (!db_path		||
		db_id == 0 		||
		!sn 			||
		!sn->hn 		||
		!sn->hn->title 	||
		!sn->hn->body[0])
	{
		return false;
	}

	// Setup temporary buffer to store the hexadecimal form of the
	// encrypted note title, as read from the database.
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));

	// Allocate memory for temporary buffer; to store the hexadecimal form
	// of the encrypted note body.
	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	// Allocate memory for temporary buffer; to store the encrypted title
	// as binary.
	enc_title_bin = calloc(HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES, sizeof(char));

	// Allocate memory for temporary buffer; to store the encrypted body
	// as binary.
	enc_body_bin = calloc(HERMETIK_NOTE_ENC_BODY_SIZE_BYTES, sizeof(char));

	// Check that the previous memory allocations succeded
	if (!enc_title_hex	||
		!enc_body_hex	||
		!enc_title_bin	||
		!enc_body_bin)
	{
		// These statements are used for more precise debugging of memory
		// allocation failures.
		if (!enc_title_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_hex\n");
		}

		if (!enc_body_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_hex\n");
		}

		if (!enc_title_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_bin\n");
		}

		if (!enc_body_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_bin\n");
		}

		goto clean_up;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_NOTE_RECORD_BY_ID_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "Could note prepare the SQL statement\n");
			fprintf(stderr, "SQLITE Error Message:\n\n%s\n\n",
					sqlite3_errmsg(db));
			goto clean_up;
		}

		// Bind the db_id to the first parameter in the SQL statement
		sqlite3_bind_int(statement, 1, db_id);

		// Execute the SQL statement and see if we've retrieved a row
		if (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the record ID to sqlite3_note->db_id
			sn->db_id = sqlite3_column_int(statement, 0);

			// Copy the encrypted note title to the temporary buffer
			memcpy(enc_title_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);

			// Copy the encrypted note body to the temporary buffer
			memcpy(enc_body_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);

			// Convert the hexadecimal form of the encrypted note title to
			// binary; and place the result in enc_title_bin.
			sodium_hex2bin(enc_title_bin,
						   HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES,
						   enc_title_hex,
						   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the encrypted note body to
			// binary; and place the result in enc_body_bin.
			sodium_hex2bin(enc_body_bin,
						   HERMETIK_NOTE_ENC_BODY_SIZE_BYTES,
						   enc_body_hex,
						   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Set the encrypted note title
			hermetik_note_set_encrypted_title
			(
				sn->hn,
				enc_title_bin,
				HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES
			);

			// Set the encrypted note body
			hermetik_note_set_encrypted_body
			(
				sn->hn,
				enc_body_bin,
				HERMETIK_NOTE_ENC_BODY_SIZE_BYTES
			);

			// We've successfully retrieved and processed a record
			success = true;
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (enc_title_hex)
	{	
		free(enc_title_hex);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	if (enc_title_bin)
	{
		free(enc_title_bin);
	}

	if (enc_body_bin)
	{
		free(enc_body_bin);
	}

	return success;
}

//	The hermetik_get_sqlite3_note_count() function returns the total
//	amount of records in the NOTE table, in the SQLite database specified
//	by *db_path.
//
unsigned int hermetik_get_sqlite3_note_count(const char *db_path)
{
	unsigned int count = 0;

	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;

	// Check for null pointer
	if (!db_path)
	{
		return 0;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check the connection attempt was successful
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_NOTE_RECORD_COUNT_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occurred preparing the SQL statement:"\
							"\n%s\n\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Execute the SQL statement and check if we retrieved a row.
		while(sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the count returned from the database
			count = sqlite3_column_int(statement, 0);
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return count;
}

//	The hermetik_get_all_sqlite3_notes() function retrieves all of the
//	records from the NOTE table, in the database specified by *db_path, and
//	copies the data to the notes in  *sns. This function returns the amount
//	of records retrieved.
//
//	This function assumes that *sns contains sufficient space to store the same
//	amount of notes as that returned from the hermetik_get_sqlite3_note_count()
//	function.
//
unsigned int hermetik_get_all_sqlite3_notes(const char *db_path,
											hermetik_sqlite3_note *(*sns)[])
{
	unsigned int count = 0;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	unsigned char *enc_title_bin = NULL;
	unsigned char *enc_body_bin = NULL;

	// Check for null pointers
	if (!db_path)
	{
		return 0;
	}

	// Allocate memory for temporary buffers
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));

	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	enc_title_bin = calloc(HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES, sizeof(char));
	enc_body_bin = calloc(HERMETIK_NOTE_ENC_BODY_SIZE_BYTES, sizeof(char));

	// Check if the previous memory allocations succeded
	if (!enc_title_hex 	||
		!enc_body_hex	||
		!enc_title_bin	||
		!enc_body_bin)
	{
		// More verbose debugging
		if (!enc_title_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_hex\n");
		}

		if (!enc_body_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_hex\n");
		}

		if (!enc_title_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_bin\n");
		}

		if (!enc_body_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_bin\n");
		}

		goto clean_up;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the previous connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_ALL_NOTE_RECORDS_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occured preparing the SQL statement:\n"\
							"%s\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Execute the SQL statement and see if we've retrieved a row
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the record ID directly to the note
			(*sns)[count]->db_id = sqlite3_column_int(statement, 0);

			// Copy the encrypted note title to the temporary buffer
			memcpy(enc_title_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);

			// Copy the encrypted note body to the temporary buffer
			memcpy(enc_body_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);

			// Convert the hexadecimal form of the encrypted note title
			// to binary, and place the result in the temporary buffer
			// enc_title_bin.
			sodium_hex2bin(enc_title_bin,
						   HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES,
						   enc_title_hex,
						   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the encrypted note body
			// to binary, and place the result in the temporary buffer
			// enc_body_bin.
			sodium_hex2bin(enc_body_bin,
						   HERMETIK_NOTE_ENC_BODY_SIZE_BYTES,
						   enc_body_hex,
						   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Set the encrypted note title
			hermetik_note_set_encrypted_title
			(
				(*sns)[count]->hn,
				enc_title_bin,
				HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES
			);

			// Set the encrypted body title
			hermetik_note_set_encrypted_body
			(
				(*sns)[count]->hn,
				enc_body_bin,
				HERMETIK_NOTE_ENC_BODY_SIZE_BYTES
			);

			// Successfully processed a record, increment the count.
			count++;

			// Zero-out the temporary buffers
			memset(enc_title_hex, 0, HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);
			memset(enc_title_bin, 0, HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES);
			memset(enc_body_hex, 0, HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);
			memset(enc_body_bin, 0, HERMETIK_NOTE_ENC_BODY_SIZE_BYTES);
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_title_bin)
	{
		free(enc_title_bin);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	if (enc_body_bin)
	{
		free(enc_body_bin);
	}

	return count;	
}

//	The hermetik_save_sqlite3_note() function writes the given note
//	to the KEYPAIR table in the SQLite database identified by *db_path.
//
bool hermetik_save_sqlite3_note(const char *db_path,
							    const hermetik_sqlite3_note *sn)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	char *insert_sql = NULL;
	int rc = 0;

	// Check for null pointers
	if (!db_path 		||
		!sn 			||
		!sn->hn 		||
		!sn->hn->title 	||
		!sn->hn->body[0])
	{
		return false;
	}

	// Allocate memory for temporary buffers
	insert_sql = calloc(HERMETIK_BUFLEN_1_MB, sizeof(char));
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));

	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	// Check if the previous memory allocations succeded
	if (!insert_sql || !enc_title_hex || !enc_body_hex)
	{
		if (!insert_sql)
		{
			fprintf(stderr, "Could not allocate memory for insert_sql\n");
		}

		if (!enc_title_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_hex\n");
		}

		if (!enc_body_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_hex\n");
		}

		fprintf(stderr, "Could not allocate enough memory!\n");
		goto clean_up;
	}

	// Convert the encrypted note title to hexadecimal and store
	// the result in enc_title_hex.
	hermetik_note_encrypted_title_to_hex(sn->hn, enc_title_hex);

	// Convert the encrypted note body to hexadecimal and store
	// the result in enc_body_hex.
	hermetik_note_encrypted_body_to_hex(sn->hn, enc_body_hex);

	// Check that the encrypted note title and body were converted successfully
	if (!(strlen(enc_title_hex) > 0) || !(strlen(enc_body_hex) > 0))
	{
		return false;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Intialize the insert_sql buffer
		sprintf(insert_sql, INSERT_NOTE_RECORD_SQL_STATEMENT,
				enc_title_hex, enc_body_hex);

		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, insert_sql,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			goto clean_up;
		}

		// Execute the SQL statement and check if it completed successfully
		if ((sqlite3_step(statement) == SQLITE_DONE))
		{
			success = true;
		}
		else
		{
			fprintf(stderr, "Could not create note record:\n\n%s\n\n",
					sqlite3_errmsg(db));
			success = false;
		}

		goto clean_up;
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (insert_sql)
	{
		free(insert_sql);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	return success;
}

//	The hermetik_get_all_sqlite3_notes_v2() function fetches all of the records
//	from the NOTE table in the SQLite database *db_path, and copies the data to
//	the *sqlite3_note(s) in **sns. This function returns the amount of records
//	retrieved.
//
unsigned int hermetik_get_all_sqlite3_notes_v2(const char *db_path,
											   hermetik_sqlite3_note **sns)
{
	unsigned int count = 0;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	unsigned char *enc_title_bin = NULL;
	unsigned char *enc_body_bin = NULL;

	// Check for null pointers
	if (!db_path)
	{
		return 0;
	}

	// Allocate memory for temporary buffers
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));

	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	enc_title_bin = calloc(HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES, sizeof(char));
	enc_body_bin = calloc(HERMETIK_NOTE_ENC_BODY_SIZE_BYTES, sizeof(char));

	// Check if the previous memory allocations succeded
	if (!enc_title_hex 	||
		!enc_body_hex	||
		!enc_title_bin	||
		!enc_body_bin)
	{
		if (!enc_title_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_hex\n");
		}

		if (!enc_body_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_hex\n");
		}

		if (!enc_title_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_bin\n");
		}

		if (!enc_body_bin)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_bin\n");
		}

		goto clean_up;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_ALL_NOTE_RECORDS_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occured preparing the SQL statement:\n"\
							"%s\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Execute the SQL statement and iterate through each row returned
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Set the note db_id
			sns[count]->db_id = sqlite3_column_int(statement, 0);

			// Copy the encrypted title to the enc_title_hex buffer
			memcpy(enc_title_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);

			// Copy the encrypted body to the enc_body_hex buffer
			memcpy(enc_body_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);

			// Convert the hexadecimal form of the encrypted title
			// to binary, and place the result in enc_title_bin.
			sodium_hex2bin(enc_title_bin,
						   HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES,
						   enc_title_hex,
						   HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the encrypted body to binary,
			// and place the result in enc_body_bin.
			sodium_hex2bin(enc_body_bin,
						   HERMETIK_NOTE_ENC_BODY_SIZE_BYTES,
						   enc_body_hex,
						   HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						   NULL, NULL, NULL);

			// Set the note's encrypted_title
			hermetik_note_set_encrypted_title
			(
				sns[count]->hn,
				enc_title_bin,
				HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES
			);

			// Set the note's encrypted_body
			hermetik_note_set_encrypted_body
			(
				sns[count]->hn,
				enc_body_bin,
				HERMETIK_NOTE_ENC_BODY_SIZE_BYTES
			);

			// Increase the count; we successfully processed a record.
			count++;

			// Zero-out the temporary buffers
			memset(enc_title_hex, 0, HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);
			memset(enc_title_bin, 0, HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES);
			memset(enc_body_hex, 0, HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);
			memset(enc_body_bin, 0, HERMETIK_NOTE_ENC_BODY_SIZE_BYTES);
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_title_bin)
	{
		free(enc_title_bin);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	if (enc_body_bin)
	{
		free(enc_body_bin);
	}

	return count;	
}

//	The hermetik_save_sqlite3_note_v2() function writes a new record
//	into the NOTE table using the encrypted data from *sn, in the SQLite
//	database identified by *db_path.
//
bool hermetik_save_sqlite3_note_v2(const char *db_path,
							       const hermetik_sqlite3_note *sn)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	int rc = 0;

	// Check for null pointers
	if (!db_path 		||
		!sn 			||
		!sn->hn 		||
		!sn->hn->title 	||
		!sn->hn->body[0])
	{
		return false;
	}

	// Allocate memory for temporary buffers
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));

	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	// Check if the previous memory allocations succeded
	if (!enc_title_hex || !enc_body_hex)
	{
		if (!enc_title_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_title_hex\n");
		}

		if (!enc_body_hex)
		{
			fprintf(stderr, "Could not allocate memory for enc_body_hex\n");
		}

		fprintf(stderr, "Could not allocate enough memory!\n");
		goto clean_up;
	}

	// Copy the hexadecimal form of the encrypted note title to enc_title_hex
	hermetik_note_encrypted_title_to_hex(sn->hn, enc_title_hex);

	// Copy the hexadecimal form of the encrypted note body to enc_body_hex
	hermetik_note_encrypted_body_to_hex(sn->hn, enc_body_hex);

	// Check that the previous copy operations succeded
	if (!(strlen(enc_title_hex) > 0) || !(strlen(enc_body_hex) > 0))
	{
		return false;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, INSERT_NOTE_RECORD_SQL_STATEMENT_V2,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			goto clean_up;
		}

		// Bind the encrypted note title to the first parameter in the
		// SQL statement.
		sqlite3_bind_text(statement, 
						  1,
						  enc_title_hex,
						  HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						  SQLITE_STATIC);

		// Bind the encrypted note body to the second parameter in the
		// SQL statement.
		sqlite3_bind_text(statement, 
						  2,
						  enc_body_hex,
						  HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  SQLITE_STATIC);

		// Execute the SQL statement and check if it was successful
		if ((sqlite3_step(statement) == SQLITE_DONE))
		{
			success = true;
		}
		else
		{
			fprintf(stderr, "Could not create note record:\n\n%s\n\n",
					sqlite3_errmsg(db));
			success = false;
		}

		goto clean_up;
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	return success;
}

//	The hermetik_update_sqlite3_note() function updates a record in the
//	NOTE table identified by *sn->db_id, in the database *db_path.
//
bool hermetik_update_sqlite3_note(const char *db_path,
								  const hermetik_sqlite3_note *sn)
{
	// Delete the old record and save a new one.
	return (hermetik_delete_sqlite3_note(db_path, sn) &&
			hermetik_save_sqlite3_note_v2(db_path, sn));
}

//	The hermetik_delete_sqlite3_note() function deletes a record
//	in the NOTE table in the database *db_path.
//
bool hermetik_delete_sqlite3_note(const char *db_path,
								  const hermetik_sqlite3_note *sn)
{
	return hermetik_delete_sqlite3_note_by_id(db_path, sn->db_id);
}

//	The hermetik_delete_sqlite3_note_by_id() function deletes a record
//	in the NOTE table identified by db_id, in the database *db_path.
//
bool hermetik_delete_sqlite3_note_by_id(const char *db_path,
										unsigned int db_id)
{
	bool success = false;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;

	// Check for null pointer and invalid db_id
	if (!db_path || db_id == 0)
	{
		return false;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, DELETE_NOTE_RECORD_BY_ID_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "Could not prepare the SQL statement: %s\n",
					sqlite3_errmsg(db));
			goto clean_up;
		}

		// Bind the db_id to the first parameter in the SQL statement
		sqlite3_bind_int(statement, 1, db_id);

		//Execute the SQL statement
		rc = sqlite3_step(statement);

		// Check if the SQL statement executed successfully
		if (rc != SQLITE_DONE)
		{
			fprintf(stderr, "\n\nReturn code:%d\n\n"\
							"SQLITE3 Error Messagr:\n\n%s\n\n"\
							"Could not delete keypair: %d\n",
							rc, sqlite3_errmsg(db), db_id);
			goto clean_up;
		}

		// The SQL statement executed successfully
		success = true;
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	return success;
}

//	The hermetik_get_all_sqlite3_keypairs_v2() function fetches all of the
//	records in the KEYPAIR TABLE, iterates over them, and stores them in
//	the *sqlite3_keypair(s) within **skps.
//
//	If this function is called with any un-initialized *sqlite3_keypair(s)
//	within **skps the behaviour is un-defined.
//
//	This function does no bounds checking. If **skps does not contain sufficient
//	memory to store all of the records within the KEYPAIR table, behaviour is
//	un-defined; more than likely, a SEGFAULT will occur. This is an obvious
//	buffer-overflow.
//
//	If you wish to make efficient use of this function. It is recommended that
//	you limit the amount of records stored in the KEYPAIR table to that which
//	your environment can allocate memory for.
//
//	e.g.
//		____________________________________________________________
//
//		size_t i = 0;
//		hermetik_sqlite3_keypair **skps = NULL;
//		skps = calloc(MAX_SAFE_AMOUNT_OF_KEYPAIRS,
//					  sizeof(hermetik_sqlite3_keypair *));
//
//		if (!skps)
//		{
//			fprintf(stderr, "Could not allocate memory for skps\n");
//			goto clean_up;
//		}
//
//		for (i = 0; i < MAX_SAFE_AMOUNT_OF_KEYPAIRS; i++)
//		{
//			skps[i] = calloc(1, sizeof(hermetik_sqlite3_keypair));
//
//			// Paranoia much...
//			if (!skps[i])
//			{
//				fprintf(stderr, "Could not allocate memory for skps[%zu]\n", i);
//				goto clean_up;
//			}
//			hermetik_init_sqlite3_keypair(skps[i]);
//		}
//
//		hermetik_get_all_sqlite3_keypairs_v2(DATABASE_FILE, skps);
//		____________________________________________________________
//
//	This function is a heap-based version of the
//	hermetik_get_all_sqlite3_keypairs() function.
//
unsigned int hermetik_get_all_sqlite3_keypairs_v2(const char *db_path,
											hermetik_sqlite3_keypair **skps)
{
	unsigned int count = 0;
	sqlite3 *db = NULL;
	sqlite3_stmt *statement = NULL;
	int rc = 0;
	char *pub_key_hex = NULL;
	char *pri_key_hex = NULL;

	// Check for null pointer
	if (!db_path)
	{
		return 0;
	}

	// Open a database connection
	rc = sqlite3_open(db_path, &db);

	// Check if the database connection attempt succeded
	if (rc)
	{
		fprintf(stderr, "Could not open database: %s\n", sqlite3_errmsg(db));
		goto clean_up;
	}
	else
	{
		// Prepare the SQL statement
		rc = sqlite3_prepare_v2(db, SELECT_ALL_KEYPAIR_RECORDS_SQL_STATEMENT,
								-1, &statement, NULL);

		// Check if the previous call succeded
		if (rc != SQLITE_OK)
		{
			fprintf(stderr, "An error occured preparing the SQL statement:\n"\
							"%s\n", sqlite3_errmsg(db));
			goto clean_up;
		}

		// Allocate memory for temporary buffers
		pub_key_hex = calloc(HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES,
							 sizeof(char));

		pri_key_hex = calloc(HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES,
							 sizeof(char));

		// Check if the memory allocation attempts succeded
		if (!pub_key_hex || !pri_key_hex)
		{
			fprintf(stderr, "Could not calloc sufficient memory!\n");
			goto clean_up;
		}

		// Execute the SQL statement and process each row returned
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			// Copy the db_id to the note
			skps[count]->db_id = sqlite3_column_int(statement, 0);

			// Copy the private key, as hexadecimal, to the
			// pri_key_hex temporary buffer
			memcpy(pri_key_hex, sqlite3_column_text(statement, 1),
				   HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);

			// Copy the public key, as hexadecimal, to its temporary buffer
			memcpy(pub_key_hex, sqlite3_column_text(statement, 2),
				   HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);

			// Copy the comment directly to the note
			memcpy(skps[count]->comment, sqlite3_column_text(statement, 3),
				   HERMETIK_SQLITE3_KEYPAIR_COMMENT_SIZE_BYTES);

			// Convert the hexadecimal form of the private key into binary and
			// save the result directly into notes[n_idx]->keypair->private_key.
			sodium_hex2bin(skps[count]->kp->private_key,
						   HERMETIK_KEYPAIR_PRIVATE_KEY_SIZE_BYTES,
						   pri_key_hex,
						   strlen(pri_key_hex),
						   NULL, NULL, NULL);

			// Convert the hexadecimal form of the public key into binary and
			// save the result directly into notes[n_idx]->keypair->public_key.
			sodium_hex2bin(skps[count]->kp->public_key,
						   HERMETIK_KEYPAIR_PUBLIC_KEY_SIZE_BYTES,
						   pub_key_hex,
						   strlen(pub_key_hex),
						   NULL, NULL, NULL);

			// Zero-out the temporary buffers
			memset(pri_key_hex, 0,
				   HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);

			memset(pub_key_hex, 0,
				   HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);

			// Successfully processed a record, increment the count.
			count++;
		}
	}

// Cleanup memory
clean_up:
	if (statement)
	{
		sqlite3_finalize(statement);
	}

	if (db)
	{
		sqlite3_close(db);
	}

	if (pub_key_hex)
	{
		free(pub_key_hex);
	}

	if (pri_key_hex)
	{
		free(pri_key_hex);
	}

	return count;
}

//	The hermetik_init_note_compare_summary() function initializes the given
//	note compare summary *ncs.
//
void hermetik_init_note_compare_summary(hermetik_note_compare_summary *ncs)
{
	// Check for null pointer
	if (!ncs)
	{
		return;
	}

	// Set each member variable to false
	ncs->identical = false;
	ncs->titles_differ = false;
	ncs->bodies_differ = false;
	ncs->enc_titles_differ = false;
	ncs->enc_bodies_differ = false;
	ncs->error_occurred = false;
}

//	The hermetik_free_note_compare_summary() function de-allocates any memory
//	allocated to a hermetik_note_compare_summary from a call to the
//	hermetik_init_note_compare_summary() function.
//
void hermetik_free_note_compare_summary(hermetik_note_compare_summary *ncs)
{
	hermetik_init_note_compare_summary(ncs);
}

//	The hermetik_note_copy() function copies the data from the *src note
//	to the *dst note.
//
void hermetik_note_copy(hermetik_note *dst,
						const hermetik_note *src)
{
	unsigned char *buf = NULL;	

	// Check for null pointers
	if (!dst 			||
		!src 			||
		!dst->title 	||
		!src->title 	||
		!dst->body[0] 	||
		!src->body[0])
	{
		return;
	}

	// Allocate memory for the temporary buffer
	buf = calloc(HERMETIK_BUFLEN_1_MB, sizeof(char));

	// Check if the memory allocation succeded
	if (!buf)
	{
		return;
	}

	// Copy the *src note title to the buffer
	hermetik_note_copy_title(src, buf);

	// Set the *dst note title
	hermetik_note_set_title(dst, buf, HERMETIK_NOTE_TITLE_SIZE_BYTES);
	memset(buf, 0, HERMETIK_BUFLEN_1_MB);

	// Copy the *src note body to the buffer
	hermetik_note_copy_body(src, buf);

	// // Set the *dst note body
	hermetik_note_set_body(dst, buf, HERMETIK_NOTE_BODY_SIZE_BYTES);
	memset(buf, 0, HERMETIK_BUFLEN_1_MB);

	// Copy the *src note encrypted title to the buffer
	hermetik_note_copy_encrypted_title(src, buf);

	// Set the *dst note encrypted title
	hermetik_note_set_encrypted_title(dst,
									  buf,
									  HERMETIK_NOTE_ENC_TITLE_SIZE_BYTES);

	// Zero-out the temporary buffer
	memset(buf, 0, HERMETIK_BUFLEN_1_MB);

	// Copy the *src note encrypted body to the buffer
	hermetik_note_copy_encrypted_body(src, buf);

	// Set the *dst note encrypted body
	hermetik_note_set_encrypted_body(dst,
									 buf,
									 HERMETIK_NOTE_ENC_BODY_SIZE_BYTES);

	// Check for null pointer
	if (buf)
	{
		// De-allocate the temporary buffer
		free(buf);
	}
}

//	The hermetik_note_compare_titles() function compares the plain-text
//	forms of two note title's.
//
bool hermetik_note_compare_titles(const hermetik_note *hn,
								  const hermetik_note *hn2)
{
	// Check for null pointers
	if (!hn			||
		!hn2		||
		!hn->title	||
		!hn2->title)
	{
		return false;
	}

	// Compare the note title's
	return hermetik_block_compare_data(hn->title, hn2->title);
}

//	The hermetik_note_compare_bodies() function compares the plain-text
//	forms of two note bodies.
//
bool hermetik_note_compare_bodies(const hermetik_note *hn,
								  const hermetik_note *hn2)
{
	size_t i = 0;
	bool match = true;

	// Check for null pointers
	if (!hn				||
		!hn2			||
		!hn->body[0]	||
		!hn2->body[0])
	{
		return false;
	}

	// Iterate through each block composing the note 'body'
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Check for null blocks
		if (!hn->body[i] || !hn2->body[i])
		{
			match = false;
			break;
		}

		// Compare the two body data blocks
		match = hermetik_block_compare_data(hn->body[i], hn2->body[i]);

		// Check if they match
		if (!match)
		{
			break;
		}
	}

	return match;
}

//	The hermetik_note_compare_encrypted_titles() function compares
//	the titles, in encrypted form, of two notes.
//
bool hermetik_note_compare_encrypted_titles(const hermetik_note *hn,
											const hermetik_note *hn2)
{
	// Check for null pointers
	if (!hn			||
		!hn2		||
		!hn->title	||
		!hn2->title)
	{
		return false;
	}

	// Compare the note title - encrypted - data blocks
	return hermetik_block_compare_encrypted_data(hn->title, hn2->title);
	
}

//	The hermetik_note_compare_encrypted_bodies() function compares the
//	encrypted bodies of two notes.
//
bool hermetik_note_compare_encrypted_bodies(const hermetik_note *hn,
											const hermetik_note *hn2)
{
	size_t i = 0;
	bool match = true;

	// Check for null pointers
	if (!hn				||
		!hn2			||
		!hn->body[0]	||
		!hn2->body[0])
	{
		return false;
	}

	// Iterate through each block composing the note body
	for (i = 0; i < HERMETIK_NOTE_BODY_SIZE_BLOCKS; i++)
	{
		// Check for null blocks
		if (!hn->body[i] || !hn2->body[i])
		{
			match = false;
			break;
		}

		// Compare the encrypted block data
		match = hermetik_block_compare_encrypted_data(hn->body[i],
													  hn2->body[i]);

		// Check if the blocks match
		if (!match)
		{
			break;
		}
	}

	return match;
}

//	The hermetik_note_compare() function compares two notes, both title's
//	and body's, in plain-text and encrypted form. This function will set
//	the members of the given hermetik_note_compare_summary *ncs so that they
//	may be examined by the caller as they wish.
//
//	As per hermetik.h
//	____________________________________________________________________________
//
//		typedef struct hermetik_note_compare_summary
//		{
//			bool identical;
//			bool titles_differ;
//			bool bodies_differ;
//			bool enc_titles_differ;
//			bool enc_bodies_differ;
//			bool error_occurred;
//		} hermetik_note_compare_summary;
//	____________________________________________________________________________
//
//
void hermetik_note_compare(const hermetik_note *hn,
						   const hermetik_note *hn2,
						   hermetik_note_compare_summary *ncs)
{
	if (!hn	|| !hn2 || !ncs)
	{
		if (ncs)
		{
			ncs->error_occurred = true;
		}

		return;
	}

	ncs->titles_differ = !hermetik_note_compare_titles(hn, hn2);
	ncs->bodies_differ = !hermetik_note_compare_bodies(hn, hn2);
	ncs->enc_titles_differ = !hermetik_note_compare_encrypted_titles(hn, hn2);
	ncs->enc_bodies_differ = !hermetik_note_compare_encrypted_bodies(hn, hn2);

	ncs->identical = (!ncs->titles_differ 		&&
					  !ncs->bodies_differ 		&&
					  !ncs->enc_titles_differ	&&
					  !ncs->enc_bodies_differ);
}



























