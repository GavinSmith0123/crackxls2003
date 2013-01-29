/* crackxls2003.c - recover encryption keys for Microsoft Excel 2003 worksheets
 *
 * Copyright (C) 2012 Gavin Smith
 * 
 * This file is distributed under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. */ 


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include <openssl/md5.h>
#include <openssl/rc4.h>

/* encrypted hash_and_verifier */
uint8_t data[32];

/* we will take the md5 hash of the last 16 bytes */
/* 80 = 16 + 16 + 48 */
uint8_t hash_and_verifier[80];

uint32_t md5[4];

/* real_key is appended with 00 00 00 00 */
/* and then md5'd which uses 64 byte blocks */
uint32_t real_key[16];

void print_hex (uint8_t *array, int n);

static void init_md5 (void)
{
	md5[0] = 0x67452301;
	md5[1] = 0xEFCDAB89;
	md5[2] = 0x98BADCFE;
	md5[3] = 0x10325476;
}

MD5_CTX md5_ctx;

void test_pass (void)
{
	/* Compute md5 */

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, real_key, 9);
	MD5_Final(md5, &md5_ctx);

	/* Decrypts bytes 32-63 then 0-31 of hash_and_verifier */

	RC4_KEY k;
	RC4_set_key (&k, 16, (unsigned char *) md5); 
	RC4 (&k, 16, data+16, hash_and_verifier+16); 
	RC4 (&k, 16, data, hash_and_verifier); 

	/* Check hash */

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, hash_and_verifier + 16, 16);
	MD5_Final(md5, &md5_ctx);

	if (0 == memcmp (md5, hash_and_verifier, 16)) {
		printf("match!\n");
		printf("key is ");
		print_hex (real_key, 5);
		print_hex (hash_and_verifier, 32);
		exit(0);
	}
}

void crack_pass (void)
{
	int i;

	/* Only works on a little endian-machine */
	do {
		do {
			test_pass();

			real_key[0]++;
		if (!(real_key[0] & 0x0000FFFF)) {
			printf("Testing ");
			print_hex (real_key, 5);
		}
		} while ((real_key[0]) != 0);

		real_key[1]++;
	} while (1);
}

void print_hex (uint8_t *array, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		printf ("%02x ", array[i]);
	}
	printf ("\n");
}


void read_hex (uint8_t *target, char *source, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		sscanf (source + 3*i, "%hhx", &target[i]);
	}
}


extern void extract (char *file_name, unsigned char *FilePass);

void load_data_from_file (char *file_name)
{
	char FilePass[54];
	extract (file_name, FilePass);
	
	print_hex(FilePass, 54);

	memcpy (data + 16, FilePass + 22, 16); /* EncryptedVerifier */
	print_hex (data + 16, 16);
	memcpy (data, FilePass + 38, 16); /* EncryptedVerifierHash */
	print_hex (data, 16);

}

void load_data (int argc, char **argv)
{
	uint8_t *real_key8;
	uint32_t i;

	if (argc <= 2) {
		fprintf(stderr, "Bad arguments.\n");
		exit(1);
	}

	/* load_data_from_file (); */
	/*
	read_hex (data+16, argv[1], 16);
	read_hex (data, argv[2], 16);
	*/
	real_key8  = (uint8_t *) real_key;

	/* clear key to zero */
	for (i = 0; i < 64; i++) {
		real_key8[i] = 0;
	}

	if (argc > 2) {
		read_hex (&real_key8[0], argv[3], 1);
		read_hex (&real_key8[1], argv[4], 1);
		read_hex (&real_key8[2], argv[5], 1);
		read_hex (&real_key8[3], argv[6], 1);
		read_hex (&real_key8[4], argv[7], 1);
	}

	real_key8[9] = 0x80; /* bit at end of data */
	real_key8[56] = 0x48; /*correct way to represent 9 */

	/* initialize verifier padding */

	int j;
	for (j = 32; j < 32 + (64 - 16); j++) {
		hash_and_verifier[j] = 0;
	}
	hash_and_verifier[32] = 0x80; /* bit at end of data */

	/* last 64 bits represent 16 */
	/* I obtained this value from a MD5 implementation that was known to
	 * work */
	hash_and_verifier[72] = 0x80;

}

/* Use getopt() to parse command line */
void parse_cmd(int argc, char **argv)
{
	int c, index;
	while (1) {
		struct option options[] =
		{
		 {"start", required_argument, 0, 's'},
		 {0, 0, 0, 0}
		};
		int option_idx = 0;

		c = getopt_long (argc, argv, "s:", options, &option_idx);

		if (c == -1) break; /* End of options */
		
		switch (c) {
		case 's': /* '--start' */
			{
			uint8_t *real_key8  = (uint8_t *) real_key;
			int n;

			n = sscanf (optarg, "%hhx %hhx %hhx %hhx %hhx",
				&real_key8[0], 
				&real_key8[1], 
				&real_key8[2], 
				&real_key8[3], 
				&real_key8[4]);
			if (n != 5) {
				fprintf(stderr,
					"Could not parse start location\n");
				exit(1);
			}
			break;
			}
		case '?':
			exit (1);
			break;
		}

	}
	if (optind == argc) {
		fprintf(stderr, "No filename provided\n");
		exit (1);
	}
	load_data_from_file (argv[optind]);
 	for (index = optind; index < argc; index++)
		printf ("Non-option argument %s\n", argv[index]);

}

main (int argc, char **argv)
{
	parse_cmd (argc, argv);
	printf("data loaded\n");
	crack_pass ();
}
