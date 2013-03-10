/* crackxls2003.c - recover encryption keys for Microsoft Excel 2003 worksheets
 *
 * Copyright (C) 2013 Gavin Smith
 * 
 * This file is distributed under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. */ 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include <time.h>
#ifdef HAVE_LIBGMP
#include <gmp.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "solar-md5/md5.h"
#include <openssl/rc4.h>

const char *file_name;
int flag_test_speed = 0;
clock_t start_time, end_time;

/* encrypted hash_and_verifier */
uint8_t data[32];

/* we will take the md5 hash of the last 16 bytes */
/* 80 = 16 + 16 + 48 */
uint8_t hash_and_verifier[80];

/* First 5 bytes are the key space */
/* 6th-9th bytes are 00 00 00 00 */
/* md5 hash is taken of first 9 bytes */
/* Full 64 bytes may be used in some implementation algorithms */
uint32_t real_key[16];

/* Used to calculate the total number of keys tested */
uint32_t real_key_start[2];

void print_hex (uint8_t *array, int n);

void cracking_stats (void)
{
#ifdef HAVE_LIBGMP
	mpz_t n_keys;
	mpf_t n_keys_f;
	char *n_keys_str;

	mpz_t mpz_low;

	double time_used;
	mpf_t mpf_time_used;

	double keys_per_second;

	end_time = clock();
	time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

	printf("CPU time used: %f seconds\n", time_used);

	/* Value of subtraction will always be positive */
	mpz_init_set_si (n_keys, real_key[1] - real_key_start[1]);

	/* multiply by 2^32 */
	mpz_mul_si (n_keys, n_keys, 1 << 16);
	mpz_mul_si (n_keys, n_keys, 1 << 16);

	/* n_keys += real_key[0] - real_key_start[0] + 1 */
	mpz_init_set_ui(mpz_low, real_key[0]);
	mpz_sub_ui(mpz_low, mpz_low, real_key_start[0]);
	mpz_add_ui(mpz_low, mpz_low, 1);
	mpz_add (n_keys, n_keys, mpz_low);
	
	n_keys_str = mpz_get_str (NULL, 10, n_keys);
	printf("Number of keys tested: %s\n", n_keys_str);
	free (n_keys_str);

	if (time_used == 0.0) return; /* Don't / by 0 */
	mpf_init (n_keys_f);
	mpf_set_z (n_keys_f, n_keys);
	mpf_init_set_d (mpf_time_used, time_used);
	mpf_div (n_keys_f, n_keys_f, mpf_time_used); 

	keys_per_second = mpf_get_d (n_keys_f);
	printf("Number of keys tested / second: %f\n", keys_per_second);
#endif /* HAVE_LIBGMP */
}
	

void test_pass (void)
{
	MD5_CTX md5_ctx;
	uint32_t md5[4];

	/* Compute md5 */

#ifdef USE_ASM
	/* places result in "md5" */
	extern void md5_compress(uint32_t *state, uint32_t *block);
	
	md5[0] = 0x67452301;
	md5[1] = 0xEFCDAB89;
	md5[2] = 0x98BADCFE;
	md5[3] = 0x10325476;

	md5_compress(md5, real_key);
#endif

#ifdef USE_REGULAR
	md5_ctx.a = 0x67452301;
	md5_ctx.b = 0xefcdab89;
	md5_ctx.c = 0x98badcfe;
	md5_ctx.d = 0x10325476;

	md5_body(&md5_ctx, real_key, 64);
	md5[0] = md5_ctx.a; 
	md5[1] = md5_ctx.b; 
	md5[2] = md5_ctx.c; 
	md5[3] = md5_ctx.d; 
#endif

	/* Decrypts bytes 32-63 then 0-31 of hash_and_verifier */

	RC4_KEY k;
	RC4_set_key (&k, 16, (unsigned char *) md5); 
	RC4 (&k, 16, data+16, hash_and_verifier+16); 
	RC4 (&k, 16, data, hash_and_verifier); 

	/* Check hash */

#ifdef USE_ASM
	md5[0] = 0x67452301;
	md5[1] = 0xEFCDAB89;
	md5[2] = 0x98BADCFE;
	md5[3] = 0x10325476;

	md5_compress(md5, (uint32_t *) (hash_and_verifier + 16));
#endif
#ifdef USE_REGULAR
	md5_ctx.a = 0x67452301;
	md5_ctx.b = 0xefcdab89;
	md5_ctx.c = 0x98badcfe;
	md5_ctx.d = 0x10325476;

	md5_body(&md5_ctx, hash_and_verifier + 16, 64);
	md5[0] = md5_ctx.a; 
	md5[1] = md5_ctx.b; 
	md5[2] = md5_ctx.c; 
	md5[3] = md5_ctx.d; 
#endif

	if (0 == memcmp (md5, hash_and_verifier, 16)) {
		printf("Key found!\n");
		printf("Key is ");
		print_hex ((uint8_t *) real_key, 5);
		if (flag_test_speed) {
			cracking_stats ();
		}
		exit(0);
	}
}

void crack_pass (void)
{
	memset(hash_and_verifier, 0, sizeof(hash_and_verifier));
	hash_and_verifier[32] = 0x80; /* bit at end of data */

	/* last 64 bits represent 16 */
	/* I obtained this value from a MD5 implementation that was known to
	 * work */
	hash_and_verifier[72] = 0x80;

	if (flag_test_speed) {
		start_time = clock();
		real_key_start [0] = real_key [0];
		real_key_start [1] = real_key [1];
	}

	/* Only works on a little endian-machine */
	do {
		do {
			test_pass();

			real_key[0]++;
		if (!(real_key[0] & 0x0000FFFF)) {
			printf("Testing .. .. ");
			print_hex ((uint8_t *) real_key + 2, 3);
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


extern void extract (const char *file_name, unsigned char *FilePass);

void load_data_from_file (const char *file_name)
{
	unsigned char FilePass[54];
	extract (file_name, FilePass);
	
	/* print_hex(FilePass, 55); */

	memcpy (data + 16, FilePass + 22, 16); /* EncryptedVerifier */
	// print_hex (data + 16, 16);
	memcpy (data, FilePass + 38, 16); /* EncryptedVerifierHash */
	// print_hex (data, 16);
	

}

extern void decrypt_file (const char *infile, const char *outfile,
		uint8_t *key);

/* Use getopt() to parse command line */
void parse_cmd(int argc, char **argv)
{
	int c;
	int decrypt_flag = 0;

	memset(real_key, 0, 64);

	while (1) {
		struct option options[] =
		{
		 {"start", required_argument, 0, 's'},
		 {"test-speed", no_argument, 0, 't'},
		 {"decrypt", required_argument, 0, 'd'},
		 {0, 0, 0, 0}
		};
		int option_idx = 0;

		c = getopt_long (argc, argv, "s:td:", options, &option_idx);

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
		case 't':
			printf("Speed testing enabled.\n");
			flag_test_speed = 1;
			break;
		case 'd': /* '--decrypt' */
			{
			uint8_t *real_key8  = (uint8_t *) real_key;
			decrypt_flag = 1;
			int n;

			n = sscanf (optarg, "%hhx %hhx %hhx %hhx %hhx",
				&real_key8[0], 
				&real_key8[1], 
				&real_key8[2], 
				&real_key8[3], 
				&real_key8[4]);
			if (n != 5) {
				fprintf(stderr,
					"Could not parse decryption key\n");
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
	file_name = argv[optind];

	if (decrypt_flag) {
		if (optind + 2 != argc) {
			fprintf(stderr, "An input and output filename "
				       "should be provided\n");
			exit (1);
		}

		char *output_file = argv[optind + 1];
		printf ("Input %s\nOutput %s\n", file_name, output_file);
		decrypt_file(file_name, output_file, (uint8_t *) real_key);
		exit (0);
	}

	load_data_from_file (file_name);
	printf("Data successfully loaded from %s\n", file_name);

	/* Initialise real_key to point to low level md5 64-byte block */
	/* This may be used by some choices of algorithm */
	uint8_t *real_key8;
	real_key8  = (uint8_t *) real_key;
	real_key8[9] = 0x80; /* bit at end of data */
	real_key8[56] = 0x48; /*correct way to represent 9 */
}

void catch_signal (int sig)
{
	printf("Program interrupted - ending program...\n");
	if (flag_test_speed) cracking_stats();
	exit(0);
}

main (int argc, char **argv)
{
#ifdef HAVE_SIGNAL_H
	signal(SIGINT, catch_signal);
#endif
	parse_cmd (argc, argv);
	crack_pass ();
}
