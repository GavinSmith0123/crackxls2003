/* Copyright (C) 2013 Gavin Smith
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gsf/gsf-utils.h>

#include <gsf/gsf-input-stdio.h>
#include <gsf/gsf-infile.h>
#include <gsf/gsf-infile-msole.h>

#include <gsf/gsf-output-stdio.h>
#include <gsf/gsf-outfile.h>
#include <gsf/gsf-outfile-msole.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/rc4.h>
#include "solar-md5/md5.h"

#include <setjmp.h>

GsfInfile *infile;
GsfOutfile *outfile;
GError    *err = NULL;

GsfInput *input_stream;
GsfOutput *output_stream;

/* decryption variables */
uint8_t rc4_key[16];
RC4_KEY rc4_state;
uint32_t block_number;
int block_pos; /* Position within 1024-byte block */

/* First 5 bytes are the found encryption key */
/* Following 4 bytes are block number (little endian?) */
uint8_t real_key[9];

/* write n bytes at data to output stream */
void put (const guint8 *data, size_t n)
{
	gsf_output_write (output_stream, n, data);
}


/* See http://msdn.microsoft.com/en-us/library/dd920360(v=office.12).aspx */
void calculate_rc4_key (void)
{
	int i;
	char dummy;

	memcpy(real_key + 5, &block_number, 4);
#if 0
	the above would be done in an endian-neutral way as follows
	real_key[5] = block_number & 0x000000FF;
	etc.
#endif

	MD5_CTX md5_ctx;
        MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, real_key, 9);
	MD5_Final((unsigned char *) rc4_key, &md5_ctx);

	RC4_set_key (&rc4_state, 16, rc4_key);

	/* Key stream must be advanced if we are not starting at
	 * the beginning of a block */

	for (i = 0; i < block_pos; i++) {
		RC4 (&rc4_state, 1, "a", &dummy);
	}
}

/* Read n bytes from input stream and decrypt them */
void dump_decrypt (int n, int suppress_decryption)
{
	guint8 const *data;
	uint8_t *decrypted_bytes;
	
	if (n == 0) return;
	decrypted_bytes = alloca(n);

	if (NULL == (data = gsf_input_read (input_stream, n, NULL))) {
		fprintf(stderr, "Error reading input file");
		exit(1);
	}
	
	RC4 (&rc4_state, n, data, decrypted_bytes);

	/* We still need to advance the RC4 keystream by the size of the
	 * record, but the original bytes are output */
	if (suppress_decryption) {
		put (data, n);
		return;
	}

	put (decrypted_bytes, n);
}

jmp_buf jmp_decryption_finished;

void decrypt_record (void)
{
	int id, size;
	guint8 id_and_size[4];
	int suppress_decryption = 0;

	static int was_at_eof = 0;

	unsigned char dummy[4] = {'a', 'a', 'a', 'a'};

        if (0 == gsf_input_read (input_stream, 4, id_and_size)) {
		fprintf(stderr, "Error reading record header\n");
		exit(1);
	}

	id = id_and_size[0] + (id_and_size[1] << 8);
	size = id_and_size[2] + (id_and_size[3] << 8);
	
	/* printf("id = %d, size = %d\n", id, size); */

	/* FilePass - record will be ignored if id = 0 */
	if (id == 47) {
		id_and_size[0] = id_and_size[1] = 0; /* ignore record */
	}
	put (id_and_size, 4);
	
	/* Skip 4 bytes in RC4 key stream */
	RC4 (&rc4_state, 4, (unsigned char *) "aaaa", dummy);

	block_pos += 4;
	if (block_pos >= 1024) {
		block_pos -= 1024;
		block_number++;
		calculate_rc4_key ();
	}

/* See http://msdn.microsoft.com/en-us/library/dd908813(v=office.12).aspx
 * for record numbers */

	/* These records are not encrypted */
	switch (id) {
	case 2057: /* BOF */
		was_at_eof = 0; /* See below */
		/* Fall through */
	case 47: /* FilePass */
	case 404: /* UsrExcl */
	case 405: /* FileLock */
	case 225: /* InterfaceHdr */
	case 406: /* RRDInfo */
	case 312: /* RRDHead */
		suppress_decryption = 1;
		break;
	case 133: /* BoundSheet8 */
		/* First four bytes ("IbPlyPos") are not encrypted */
		/* Second arg means not to decrypt */
		dump_decrypt(4, 1);

		block_pos += 4;
		if (block_pos >= 1024) {
			block_pos -= 1024;
			block_number++;
			calculate_rc4_key ();
		}
		
		/* Process rest of record using code below */
		size -= 4;
		break;
	}
	
	/* EOF */
	/* Some files seem to have a lot of 00 bytes at the end of the
	 * Workbook stream which should not be read. (Unless the number of
	 * these bytes is a multiple of 4, it will break when we try to read
	 * the ID and record size.) This may be caused by an incorrect stream
	 * length. Hence, we should stop reading when we reach an EOF record
	 * which is not followed by a BOF record. As long as the junk bytes
	 * are only 00's and there are at least four of them, it will suffice
	 * to check for a null record following an EOF record. */
	if (id == 10) {
		was_at_eof = 1;
	}
	if (id == 0 && was_at_eof) {
		/* Return 1 from setjmp */
		longjmp(jmp_decryption_finished, 1);
	}

	
	/* Record body split across several blocks */
	if (size + block_pos >= 1024) {
		/* Process part at beginning */
		dump_decrypt(1024 - block_pos, suppress_decryption);
		size -= (1024 - block_pos);

		block_pos = 0;
		block_number++;
		calculate_rc4_key ();
	
		/* Process middle */
		while (size >= 1024) {
			dump_decrypt(1024, suppress_decryption);
			size -= 1024;
			block_number++;
			calculate_rc4_key ();
		}
	}
	dump_decrypt(size, suppress_decryption);
	block_pos += size;
}

/* Decrypt input_stream to output_stream */
void decrypt (void)
{
	if (gsf_input_size (input_stream) > 0) {
		block_number = 0;
		block_pos = 0;
		calculate_rc4_key ();

		int n;

		if (setjmp(jmp_decryption_finished) == 0) {
		while (n = gsf_input_remaining (input_stream) > 0) {
			/* printf("%d bytes left in stream\n", n); */
			decrypt_record();
		}
		} else {
			printf("Null bytes at end of stream\n");
		}
		/* printf("%d bytes left in stream\n", n); */
		gsf_output_close(output_stream);
		g_object_unref (G_OBJECT (output_stream));
	}
	g_object_unref (G_OBJECT (input_stream));
}

/* Copy input_stream to output_stream */
void copy (void)
{
	if (gsf_input_size (input_stream) > 0) {
		guint8 const *data;
		size_t len;

		while ((len = gsf_input_remaining (input_stream)) > 0) {
			if (len > 1024)
				len = 1024;
			if (NULL == (data =
			    gsf_input_read (input_stream, len, NULL))) {
				fprintf(stderr, "Error copying stream\n");
				return;
			}
			put (data, len);
		}

		gsf_output_close(output_stream);
		g_object_unref (G_OBJECT (output_stream));
	}
	g_object_unref (G_OBJECT (input_stream));
}

/* Copy or decrypt a structured file or storage */
void copy_or_decrypt_tree (int decryptp,
		GsfInfile *infile, GsfOutfile *outfile)
{
        int i;
	for (i = 0 ; i < gsf_infile_num_children (infile); i++) {
		GsfInput *child_in = gsf_infile_child_by_index (infile, i);
		GsfOutput *child_out;

		gboolean is_dir;

		/* Check if child is another storage */
		is_dir = (GSF_IS_INFILE (child_in) &&
			gsf_infile_num_children (GSF_INFILE(child_in)) >= 0);

		child_out = gsf_outfile_new_child (
			outfile,
			gsf_infile_name_by_index (infile, i),
			is_dir);

		if (! is_dir) {
                        /* Child is a stream */
			input_stream = child_in;
			output_stream = child_out;
			if (! decryptp) {
				copy ();
			} else {
				decrypt();
			}
		} else {
			/* Child is a storage, so recursively process */
			copy_or_decrypt_tree (
				decryptp,
				GSF_INFILE (child_in),
				GSF_OUTFILE (child_out));
		}
	}
}

void decrypt_file (const char *infile_name, const char *outfile_name,
                   uint8_t *key)
{
	int i;
	GsfInput *input;

	GsfOutput *output;

	gsf_init ();

	/* Load input file for reading */
	input = gsf_input_stdio_new (infile_name, &err);
	infile = gsf_infile_msole_new (input, &err);
	g_object_unref (G_OBJECT (input));

	/* Load output file for writing */
	output = gsf_output_stdio_new (outfile_name, &err);
	outfile = gsf_outfile_msole_new (output);
	g_object_unref (G_OBJECT (output));

	/* Copy encryption key from arguments */
	for (i = 0; i < 5; i++) {
		real_key[i] = key[i];
	}

	for (i = 0 ; i < gsf_infile_num_children (infile) ; i++) {
		const char *child_name = gsf_infile_name_by_index(infile, i);

		gboolean is_dir;

		/* Check if child is a storage (storages in OLE compound
                 * files are like subdirectories) */
		is_dir = (GSF_IS_INFILE (input_stream) &&
			gsf_infile_num_children (GSF_INFILE(input_stream))
			>= 0);

		/* Global variables used by copy() or decrypt() functions
		 * We may also pass the values to copy_or_decrypt_tree(),
		 * which will end up redefining the global variables when
		 * it calls copy() or decrypt() itself */
		input_stream = gsf_infile_child_by_index (infile, i);
		output_stream = gsf_outfile_new_child (
			outfile,
			child_name,
			is_dir);

		if (is_dir) {
			/* Pivot Cache storage */
 /* See http://msdn.microsoft.com/en-us/library/dd910065(v=office.12).aspx */ 
			if (0 == strcmp (child_name, "_SX_DB_CUR")) {
				/* printf("Pivot Cache storage found\n"); */
				copy_or_decrypt_tree (
					1, /* decrypt */
					GSF_INFILE (input_stream),
					GSF_OUTFILE (output_stream));
			} else {
				copy_or_decrypt_tree (
					0, /* copy */
					GSF_INFILE (input_stream),
					GSF_OUTFILE (output_stream));
			}
                        /* Note: copy_or_decrypt_tree may have changed
                         * input_stream or output_stream by this point, but
                         * we don't use those variables after here. */
		} else {
			if (0 == strcmp (child_name, "Workbook")) {
				/* printf("Workbook stream found\n"); */
				decrypt ();
			} else if (0 == strcmp (child_name, "Revision Log")) {
				/* printf("Revision Log stream found\n"); */
				decrypt ();
			} else {
				copy ();
			}
		}
	}

	gsf_output_close(GSF_OUTPUT(outfile));
	gsf_shutdown ();
}

