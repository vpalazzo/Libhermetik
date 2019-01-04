/*
 *      Copyright (c) 2018 Victor Palazzo <palazzov@sheridancollege.ca>
 *
 *      Permission to use, copy, modify, and distribute this software for any
 *      purpose with or without fee is hereby granted, provided that the above
 *      copyright notice and this permission notice appear in all copies.
 *
 *      THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *      WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *      MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *      ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *      WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *      ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *      OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/******************************* Update Log ************************************
 
Date            Developer Name          Description
----------      --------------          ----------------------------------------
25-11-2018      Victor Palazzo          Created this file.

*******************************************************************************/

#include <hermetik.h>

void test_hermetik_str_split(void);
void list_keypairs(void);
void list_keypairs_v2(void);
void list_notes(void);
void list_notes_v2(void);
void compare_notes_test(void);
void benchmark(void);
void drop_create_db(void);

#define DATABASE_FILE   "/Users/victor.palazzo/projects/libhermetik/hermetik-db"
#define DATABASE_FILE_RAM   ":memory:"
#define DEFAULT_KEYPAIR_DB_ID	1

#define BENCHMARK_KEYPAIRS_TO_GENERATE		1000
#define BENCHMARK_NOTES_TO_GENERATE			1000
#define TEST_NOTE_DB_ID						2
#define COMMENT	"My default keypair"
#define MESSAGE "My super secret message"
#define NOTE_TITLE	"My secret note"
#define NOTE_BODY	"abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
					"acaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
					"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"\
					"cccccccccccccccccccccccccccccccccccccccccccccccccc"\
					"dddddddddddddddddddddddddddddddddddddddddddddddddd"\
					"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"\
					"ffffffffffffffffffffffffffffffffffffffffffffffffff"\
					"gggggggggggggggggggggggggggggggggggggggggggggggggg"\
					"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"\
					"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"\
					"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj"\
					"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"\
					"llllllllllllllllllllllllllllllllllllllllllllllllll"\
					"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"\
					"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"\
					"oooooooooooooooooooooooooooooooooooooooooooooooooo"\
					"pppppppppppppppppppppppppppppppppppppppppppppppppp"\
					"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"\
					"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"\
					"sssssssssssssssssssssssssssssssssssssssssssssssss!"

void drop_create_db()
{
	hermetik_drop_sqlite3_keypair_table(DATABASE_FILE);
	hermetik_drop_sqlite3_note_table(DATABASE_FILE);
}

void compare_notes_test()
{
	hermetik_note *hn = NULL;
	hermetik_note *hn_copy = NULL;
	hermetik_keypair *kp = NULL;
	hermetik_note_compare_summary *ncs = NULL;
	int exit_code = 0;

	hn = calloc(1, sizeof(hermetik_note));
	hn_copy = calloc(1, sizeof(hermetik_note));
	kp = calloc(1, sizeof(hermetik_keypair));
	ncs = calloc(1, sizeof(hermetik_note_compare_summary));

	if (!hn || !hn_copy || !kp || !ncs)
	{
		exit_code = 500;
		goto clean_up;
	}

	hermetik_init_note(hn);
	hermetik_init_note(hn_copy);
	hermetik_init_keypair(kp);
	hermetik_init_note_compare_summary(ncs);

	if (!hermetik_keypair_generate_keys(kp))
	{
		exit_code = 501;
		goto clean_up;
	}

	hermetik_note_set_title(hn, NOTE_TITLE, strlen(NOTE_TITLE));
	hermetik_note_set_body(hn, NOTE_BODY, strlen(NOTE_BODY));

	if (!hermetik_note_encrypt_with_keypair(hn, kp))
	{
		exit_code = 502;
		goto clean_up;
	}

	hermetik_note_copy(hn_copy, hn);
	hermetik_note_compare(hn, hn_copy, ncs);

	if (!ncs->identical)
	{
		printf("Title differ:  %d\n"\
			   "Bodies differ: %d\n"\
			   "Encrypted titles differ: %d\n"\
			   "Encrypted bodies differ: %d\n"\
			   "Error occurred: %d\n",
			   ncs->titles_differ,
			   ncs->bodies_differ,
			   ncs->enc_titles_differ,
			   ncs->enc_bodies_differ,
			   ncs->error_occurred);

//		printf("Hex dump note #1\n\n");
//		hermetik_note_hex_dump_encrypted_body(hn);
//
//		printf("Hex dump note #2\n\n");
//		hermetik_note_hex_dump_encrypted_body(hn);

		goto clean_up;
	}

	printf("Both notes are identical after copy\nTest completed\n");

clean_up:
	if (hn)
	{
		hermetik_free_note(hn);
		free(hn);
	}

	if (hn_copy)
	{
		hermetik_free_note(hn_copy);
		free(hn_copy);
	}

	if (kp)
	{
		hermetik_free_keypair(kp);
		free(kp);
	}

	if (ncs)
	{
		hermetik_free_note_compare_summary(ncs);
		free(ncs);
	}

	if (exit_code != 0)
	{
		fprintf(stderr, "compare_notes_test() Exit Code: %d\n\n", exit_code);
	}
}

void benchmark()
{
	hermetik_sqlite3_note *sn = NULL;
	hermetik_sqlite3_keypair *skp = NULL;
	hermetik_sqlite3_keypair *b_skp = NULL;
	hermetik_sqlite3_note **sns = NULL;
	int exit_code = 0;
	int i = 0;
    int count = 0;
    unsigned char *title = NULL;
    unsigned char *body = NULL;
    char *enc_title_hex = NULL;
    char *enc_body_hex = NULL;

	sn = calloc(1, sizeof(hermetik_sqlite3_note));
	skp = calloc(1, sizeof(hermetik_sqlite3_keypair));
	b_skp = calloc(1, sizeof(hermetik_sqlite3_keypair));
	title = calloc(HERMETIK_NOTE_TITLE_SIZE_BYTES, sizeof(char));
    body = calloc(HERMETIK_NOTE_BODY_SIZE_BYTES, sizeof(char));
    enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
                           sizeof(char));
    enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
                          sizeof(char));

	if (!sn || !skp || !b_skp || !title || !body || !enc_title_hex ||
		!enc_body_hex)
	{
		fprintf(stderr, "Could not calloc() memory\n");
		return;
	}

	printf("Beginning Benchmark:\n"\
		   "Generating->Saving %d keypairs\n",
		   BENCHMARK_KEYPAIRS_TO_GENERATE);

	hermetik_init_sqlite3_keypair(b_skp);

	for (i = 0; i < BENCHMARK_KEYPAIRS_TO_GENERATE; i++)
	{
		if (!hermetik_keypair_generate_keys(b_skp->kp))
		{
			exit_code = 303;
			goto clean_up;
		}

		if (i == 0)
		{
			hermetik_sqlite3_keypair_set_comment(b_skp, COMMENT,
												 strlen(COMMENT));
		}

		if (!hermetik_save_sqlite3_keypair(DATABASE_FILE, b_skp))
		{
			exit_code = 304;
			goto clean_up;
		}

		if (i == 0)
		{
			hermetik_sqlite3_keypair_set_comment(b_skp, "",
												 strlen(""));
		}

		hermetik_keypair_zero_out(b_skp->kp);
	}

	printf("Keypair benchmark complete\n\n");

	hermetik_init_sqlite3_keypair(skp);

	if (!hermetik_get_sqlite3_keypair_by_id(DATABASE_FILE,
											DEFAULT_KEYPAIR_DB_ID,
											skp))
	{
		exit_code = 300;
		goto clean_up;
	}

	printf("Beginning Benchmark:\n"\
		   "Generating->Encrypting->Saving %d notes\n",
		   BENCHMARK_NOTES_TO_GENERATE);

	hermetik_init_sqlite3_note(sn);

	for (i = 0; i < BENCHMARK_NOTES_TO_GENERATE; i++)
	{
		hermetik_note_set_title(sn->hn, NOTE_TITLE, strlen(NOTE_TITLE));
		hermetik_note_set_body(sn->hn, NOTE_BODY, strlen(NOTE_BODY));

		if (!hermetik_note_encrypt_with_keypair(sn->hn, skp->kp))
		{
			exit_code = 301;
			goto clean_up;
		}

		if (!hermetik_save_sqlite3_note(DATABASE_FILE, sn))
		{
			exit_code = 302;
			goto clean_up;
		}

		hermetik_note_zero_out(sn->hn);
	}

	printf("Note encryption benchmark complete\n\n");

	count = hermetik_get_sqlite3_note_count(DATABASE_FILE);
	printf("Beginning Benchmark:\n"\
		   "Fetching->Decrypting %d notes\n",
		   count);

    sns = calloc(count, sizeof(hermetik_sqlite3_note *));

    if (!sns)
    {
        exit_code = 99;
        goto clean_up;
    }

    for (i = 0; i < count; i++)
    {
        sns[i] = calloc(1, sizeof(hermetik_sqlite3_note));
        if (!sns[i])
        {
            exit_code  = 100;
            goto clean_up;
        }
        hermetik_init_sqlite3_note(sns[i]);
    }

    hermetik_get_all_sqlite3_notes_v2(DATABASE_FILE, sns);

    printf("Total notes retrieved: %d\n", count);

    for (i = 0; i < count; i++)
    {
        if (!hermetik_note_decrypt_with_keypair(sns[i]->hn, skp->kp))
        {
            printf("Could not decrypt note #%d\n\n",
                   (*sns + count)->db_id);
            hermetik_note_encrypted_title_to_hex(sns[i]->hn, enc_title_hex);
            hermetik_note_encrypted_body_to_hex(sns[i]->hn, enc_body_hex);
            printf("note->title (encrypted - hex):\n\n%s\n\n", enc_title_hex);
            printf("note->body (encrypted - hex):\n\n%s\n\n", enc_body_hex);
			hermetik_note_hex_dump_body(sns[i]->hn);
			exit_code = 169;
			goto clean_up;
        }

        hermetik_free_sqlite3_note(sns[i]);
        free(sns[i]);
	}

	printf("Note decryption benchmark complete\n\n");

clean_up:
	if (sn)
	{
		hermetik_free_sqlite3_note(sn);
		free(sn);
	}

	if (skp)
	{
		hermetik_free_sqlite3_keypair(skp);
		free(skp);
	}

	if (b_skp)
	{
		hermetik_free_sqlite3_keypair(b_skp);
		free(b_skp);
	}

 	if (title)
    {
        free(title);
    }

    if (body)
    {
        free(body);
    }

    if (enc_title_hex)
    {
        free(enc_title_hex);
    }

    if (enc_body_hex)
    {
        free(enc_body_hex);
    }

    if (sns)
    {
        free(sns);
    }

	if (exit_code != 0)
	{
		fprintf(stderr, "benchmark() Exit Code: %d\n\n", exit_code);
	}
}

void test_hermetik_str_split()
{
//	char csv[] = "one,two,three";
//	char **tokens = NULL;
//	int i = 0;
//
//	tokens = hermetik_str_split(csv, ',');
//
//	if (tokens)
//	{
//		for (i = 0; *(tokens + i); i++)
//		{
//			printf("Token [%d]: %s\n", i, *(tokens + i));
//			free(*(tokens + i));
//		}
//
//		printf("\n");
//		free(tokens);
//	}
}

void list_keypairs()
{
	int i = 0;
	int count = 0;
	int secondary_count = 0;
	hermetik_sqlite3_keypair *skps[100];
	hermetik_sqlite3_keypair *(*skps_ref)[] = &skps;
	char pub_key_hex[HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES] = { '\0' };
	char pri_key_hex[HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES] = { '\0' };

	count = hermetik_get_sqlite3_keypair_count(DATABASE_FILE);

	for (i = 0; i < count; i++)
	{
		skps[i] = malloc(sizeof(hermetik_sqlite3_keypair));
		hermetik_init_sqlite3_keypair(skps[i]);
	}

	secondary_count = hermetik_get_all_sqlite3_keypairs(DATABASE_FILE,
														skps_ref);

	printf("Total keys retrieved: %d\n", secondary_count);

	for (i = 0; i < count; i++)
	{
		hermetik_keypair_public_key_to_hex(skps[i]->kp, pub_key_hex);
		hermetik_keypair_private_key_to_hex(skps[i]->kp, pri_key_hex);

		printf("Keypair->db_id:       %d\n"\
			   "       ->public_key:  %s\n"\
			   "       ->private_key: %s\n"\
			   "       ->comment: %s\n",
			   skps[i]->db_id,
			   pub_key_hex,
			   pri_key_hex,
			   skps[i]->comment);

		memset(pub_key_hex, 0, HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);
		memset(pri_key_hex, 0, HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);
		
		hermetik_free_sqlite3_keypair(skps[i]);
		free(skps[i]);
	}
}

void list_keypairs_v2()
{
	int i = 0;
	int count = 0;
	int secondary_count = 0;
	hermetik_sqlite3_keypair **skps = NULL;
	char *pub_key_hex = NULL;
	char *pri_key_hex = NULL;
	int exit_code = 0;

	count = hermetik_get_sqlite3_keypair_count(DATABASE_FILE);

	pub_key_hex = calloc(HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES, 
						 sizeof(char));
	pri_key_hex = calloc(HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES,
						 sizeof(char));
	skps = calloc(count, sizeof(hermetik_sqlite3_keypair *));

	if (!skps || !pub_key_hex || !skps)
	{
		exit_code = 200;
		goto clean_up;
	}

	for (i = 0; i < count; i++)
	{
		skps[i] = calloc(1, sizeof(hermetik_sqlite3_keypair));
		hermetik_init_sqlite3_keypair(skps[i]);

		if (!skps[i] 	 				||
			!skps[i]->kp 				||
			!skps[i]->kp->public_key	||
			!skps[i]->kp->private_key	||
			!skps[i]->comment)
		{
			exit_code = 201;
			goto clean_up;
		}
	}

	secondary_count = hermetik_get_all_sqlite3_keypairs_v2(DATABASE_FILE,skps);
	printf("Original count: %d\n", count);
	printf("Total keys retrieved: %d\n", secondary_count);

	for (i = 0; i < count; i++)
	{
		hermetik_keypair_public_key_to_hex(skps[i]->kp, pub_key_hex);
		hermetik_keypair_private_key_to_hex(skps[i]->kp, pri_key_hex);

		printf("Keypair->db_id:       %d\n"\
			   "       ->public_key:  %s\n"\
			   "       ->private_key: %s\n"\
			   "       ->comment: %s\n",
			   skps[i]->db_id,
			   pub_key_hex,
			   pri_key_hex,
			   skps[i]->comment);

		hermetik_free_sqlite3_keypair(skps[i]);
		free(skps[i]);

		memset(pub_key_hex, 0, HERMETIK_KEYPAIR_PUBLIC_KEY_AS_HEX_SIZE_BYTES);
		memset(pri_key_hex, 0, HERMETIK_KEYPAIR_PRIVATE_KEY_AS_HEX_SIZE_BYTES);
	}

clean_up:
	if (skps)
	{
		free(skps);
	}

	if (exit_code != 0)
	{
		fprintf(stderr, "list_notes_v2() Exit Code: %d\n\n", exit_code);
	}
}


void list_notes()
{
	int i = 0;
	int count = 0;
	int secondary_count = 0;
	unsigned char *title = NULL;
	unsigned char *body = NULL;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	int exit_code = 0;
	hermetik_sqlite3_keypair *skp = NULL;
	hermetik_sqlite3_note *sns[1000];
	hermetik_sqlite3_note *(*sns_ref)[] = &sns;

	skp = calloc(1, sizeof(hermetik_sqlite3_keypair));
	title = calloc(HERMETIK_NOTE_TITLE_SIZE_BYTES, sizeof(char));
	body = calloc(HERMETIK_NOTE_BODY_SIZE_BYTES, sizeof(char));
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));
	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	if (!skp || !title || !body || !enc_title_hex || !enc_body_hex)
	{
		exit_code = 1;
		goto clean_up;
	}

	hermetik_init_sqlite3_keypair(skp);

	if (!hermetik_get_sqlite3_keypair_by_id(DATABASE_FILE,
											DEFAULT_KEYPAIR_DB_ID,
											skp))
	{
		exit_code = 2;
		goto clean_up;
	}

	count = hermetik_get_sqlite3_note_count(DATABASE_FILE);

	for (i = 0; i < count; i++)
	{
		sns[i] = calloc(1, sizeof(hermetik_sqlite3_note));
		hermetik_init_sqlite3_note(sns[i]);
	}

	hermetik_get_all_sqlite3_notes(DATABASE_FILE, sns_ref);

	printf("Total notes retrieved: %d\n", count);

	for (i = 0; i < count; i++)
	{
		if (!hermetik_note_decrypt_with_keypair(sns[i]->hn, skp->kp))
		{
			printf("Could not decrypt note #%d\n\n",
				   sns[i]->db_id);
			hermetik_note_encrypted_title_to_hex(sns[i]->hn, enc_title_hex);
			hermetik_note_encrypted_body_to_hex(sns[i]->hn, enc_body_hex);
			printf("note->title (encrypted - hex):\n\n%s\n\n", enc_title_hex);
			printf("note->body (encrypted - hex):\n\n%s\n\n", enc_body_hex);
			continue;
		}

		printf("Successfully decrypted note #%d\n\n", sns[i]->db_id);
		hermetik_note_copy_title(sns[i]->hn, title);
		hermetik_note_copy_body(sns[i]->hn, body);
		printf("note->title (decrypted):\n\n%s\n\n", title);
		printf("note->body (decrypted):\n\n%s\n\n", body);

		hermetik_free_sqlite3_note(sns[i]);
		free(sns[i]);

		memset(title, 0, HERMETIK_NOTE_TITLE_SIZE_BYTES);
		memset(body, 0, HERMETIK_NOTE_BODY_SIZE_BYTES);
		memset(enc_title_hex, 0, HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);
		memset(enc_body_hex, 0, HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);
	}

clean_up:
	if (skp)
	{
		hermetik_free_sqlite3_keypair(skp);
		free(skp);
	}

	if (title)
	{
		free(title);
	}

	if (body)
	{
		free(body);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	if (exit_code != 0)
	{
		printf("list_notes() exit_code: %d\n\n", exit_code);
	}
}

void list_notes_v2()
{
	int i = 0;
	int count = 0;
	int secondary_count = 0;
	unsigned char *title = NULL;
	unsigned char *body = NULL;
	char *enc_title_hex = NULL;
	char *enc_body_hex = NULL;
	int exit_code = 0;
	hermetik_sqlite3_keypair *skp = NULL;
	hermetik_sqlite3_note **sns;

	skp = calloc(1, sizeof(hermetik_sqlite3_keypair));
	title = calloc(HERMETIK_NOTE_TITLE_SIZE_BYTES, sizeof(char));
	body = calloc(HERMETIK_NOTE_BODY_SIZE_BYTES, sizeof(char));
	enc_title_hex = calloc(HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES,
						   sizeof(char));
	enc_body_hex = calloc(HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES,
						  sizeof(char));

	if (!skp || !title || !body || !enc_title_hex || !enc_body_hex)
	{
		exit_code = 1;
		goto clean_up;
	}

	hermetik_init_sqlite3_keypair(skp);

	if (!hermetik_get_sqlite3_keypair_by_id(DATABASE_FILE,
											DEFAULT_KEYPAIR_DB_ID,
											skp))
	{
		exit_code = 2;
		goto clean_up;
	}

	count = hermetik_get_sqlite3_note_count(DATABASE_FILE);
	sns = calloc(count, sizeof(hermetik_sqlite3_note *));

	if (!sns)
	{
		exit_code = 99;
		goto clean_up;
	}

	for (i = 0; i < count; i++)
	{
		sns[i] = calloc(1, sizeof(hermetik_sqlite3_note));
		if (!sns[i])
		{
			exit_code  = 100;
			goto clean_up;
		}
		hermetik_init_sqlite3_note(sns[i]);
	}

	hermetik_get_all_sqlite3_notes_v2(DATABASE_FILE, sns);

	printf("Total notes retrieved: %d\n", count);

	for (i = 0; i < count; i++)
	{
		if (!hermetik_note_decrypt_with_keypair(sns[i]->hn, skp->kp))
		{
			printf("Could not decrypt note #%d\n\n",
				   (*sns + count)->db_id);
			hermetik_note_encrypted_title_to_hex(sns[i]->hn, enc_title_hex);
			hermetik_note_encrypted_body_to_hex(sns[i]->hn, enc_body_hex);
			printf("note->title (encrypted - hex):\n\n%s\n\n", enc_title_hex);
			printf("note->body (encrypted - hex):\n\n%s\n\n", enc_body_hex);
			continue;
		}

		printf("Successfully decrypted note #%d\n\n", sns[i]->db_id);
		hermetik_note_copy_title(sns[i]->hn, title);
		hermetik_note_copy_body(sns[i]->hn, body);
		printf("note->title (decrypted):\n\n%s\n\n", title);
		printf("note->body (decrypted):\n\n%s\n\n", body);

		hermetik_free_sqlite3_note(sns[i]);
		free(sns[i]);

		memset(title, 0, HERMETIK_NOTE_TITLE_SIZE_BYTES);
		memset(body, 0, HERMETIK_NOTE_BODY_SIZE_BYTES);
		memset(enc_title_hex, 0, HERMETIK_NOTE_ENC_TITLE_AS_HEX_SIZE_BYTES);
		memset(enc_body_hex, 0, HERMETIK_NOTE_ENC_BODY_AS_HEX_SIZE_BYTES);
	}

clean_up:
	if (skp)
	{
		hermetik_free_sqlite3_keypair(skp);
		free(skp);
	}

	if (title)
	{
		free(title);
	}

	if (body)
	{
		free(body);
	}

	if (enc_title_hex)
	{
		free(enc_title_hex);
	}

	if (enc_body_hex)
	{
		free(enc_body_hex);
	}

	if (sns)
	{
		free(sns);
	}

	if (exit_code != 0)
	{
		printf("list_notes() exit_code: %d\n\n", exit_code);
	}
}

					


int main(int argc, char *argv[])
{
	if (sodium_init() == -1)
	{
		fprintf(stderr, "libsodium failed to initialize!\n");
		exit(2);
	}

	// TODO: create hermetik_drop_create_db() function
	drop_create_db();

	if (!hermetik_create_sqlite3_keypair_table(DATABASE_FILE))
	{
		fprintf(stderr, "Could not create KEYPAIR table!\n");
		exit(3);
	}

	if (!hermetik_create_sqlite3_note_table(DATABASE_FILE))
	{
		fprintf(stderr, "Could not create NOTE table\n");
		exit(4);
	}

	printf("------------------------ Benchmark ----------------------------\n");
	benchmark();
	printf("---------------------------------------------------------------\n");
//	printf("-------------------- Note Copy & Compare Test -----------------\n");
//	compare_notes_test();
//	printf("---------------------------------------------------------------\n");
//	printf("------------------------ Listing Notes ------------------------\n");
//	list_notes();
//	printf("---------------------------------------------------------------\n");
//	printf("------------------------ Listing Keypairs ---------------------\n");
//	list_keypairs();
//	printf("---------------------------------------------------------------\n");
//	printf("------------------------ Listing Notes (v2) -------------------\n");
//	list_notes_v2();
//	printf("---------------------------------------------------------------\n");
//	printf("------------------------ Listing Keypairs (v2) ----------------\n");
//	list_keypairs_v2();
//	printf("---------------------------------------------------------------\n");
}


