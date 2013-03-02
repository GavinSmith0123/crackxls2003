/* test decrypting monkey.xls */
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

#include <openssl/rc4.h>
#include <openssl/md5.h>

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
}

/* Read n bytes from input stream and decrypt them */
void dump_decrypt (int n, int suppress_decryption)
{
	guint8 const *data;
	uint8_t *decrypted_bytes;
	
	if (n == 0) return;
	decrypted_bytes = alloca(n);

	if (NULL == (data = gsf_input_read (input_stream, n, NULL))) {
		g_warning ("error reading ?");
		exit(1);
	}
	
	RC4 (&rc4_state, n, data, decrypted_bytes);

	/* We still need to advance the RC4 keystream by the size of the record,
	 * but the original bytes are output */
	if (suppress_decryption) {
		put (data, n);
		return;
	}

	put (decrypted_bytes, n);
}

void decrypt_record (void)
{
	int id, size;
	guint8 id_and_size[4];
	int suppress_decryption = 0;

	char dummy[4] = {'a', 'a', 'a', 'a'};

        gsf_input_read (input_stream, 4, id_and_size);
	if (id_and_size == 0) {
		g_warning ("error reading ?");
		exit(1);
	}

	id = id_and_size[0] + (id_and_size[1] << 8);
	size = id_and_size[2] + (id_and_size[3] << 8);
	
	/* Skip 4 bytes in RC4 key stream */
	RC4 (&rc4_state, 4, "aaaa", dummy);

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
	case 47: /* FilePass */
		id_and_size[0] = id_and_size[1] = 0; /* ignore record */
	case 2057: /* BOF */
	case 404: /* UsrExcl */
	case 405: /* FileLock */
	case 225: /* InterfaceHdr */
	case 406: /* RRDInfo */
	case 312: /* RRDHead */
		suppress_decryption = 1;
		break;
	case 133: /* BoundSheet8 */
		break;
		/* Requires special attention - not implemented yet */
	}
	put (id_and_size, 4);
	
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

/* decryption of stream */
void decrypt (int index)
{
	int i;

	input_stream = gsf_infile_child_by_index (infile, index);
	if (gsf_input_size (input_stream) > 0) {
		guint8 const *data;
		size_t len;

		output_stream = gsf_outfile_new_child (
				outfile,
				gsf_infile_name_by_index(infile, index),
				FALSE);
		block_number = 0;
		block_pos = 0;

		calculate_rc4_key ();

		while ((len = gsf_input_remaining (input_stream)) > 0) {
			decrypt_record();
		}
		gsf_output_close(output_stream);
		g_object_unref (G_OBJECT (output_stream));
	}
	g_object_unref (G_OBJECT (input_stream));
}

void copy (int index)
{
	int i;

	input_stream = gsf_infile_child_by_index (infile, index);
	if (gsf_input_size (input_stream) > 0) {
		guint8 const *data;
		size_t len;

		output_stream = gsf_outfile_new_child (
				outfile,
				gsf_infile_name_by_index(infile, index),
			       	FALSE);

		while ((len = gsf_input_remaining (input_stream)) > 0) {
			if (len > 1024)
				len = 1024;
			if (NULL == (data = gsf_input_read (input_stream, len, NULL))) {
				g_warning ("error reading ?");
				return;
			}
			put (data, len);
		}

		gsf_output_close(output_stream);
		g_object_unref (G_OBJECT (output_stream));
	}
	g_object_unref (G_OBJECT (input_stream));
}

void decrypt_file (char *infile_name, char *outfile_name, uint8_t *key)
{
	int i;
	GsfInput *input;

	GsfOutput *output;

	gsf_init ();

	/* Load input file for reading */
	input = gsf_input_stdio_new (infile_name, &err);
	infile = gsf_infile_msole_new (input, &err);
	g_object_unref (G_OBJECT (input));

	/* Load "monkey-decrypt.xls" for writing */
	output = gsf_output_stdio_new (outfile_name, &err);
	outfile = gsf_outfile_msole_new (output);
	g_object_unref (G_OBJECT (output));

	/* Copy encryption key from arguments */
	for (i = 0; i < 5; i++) {
		real_key[i] = key[i];
	}

	for (i = 0 ; i < gsf_infile_num_children (infile) ; i++) {
		if (0 == strcmp ("Workbook", gsf_infile_name_by_index(infile, i))) {
			decrypt (i);
		} else {
			copy (i);
		}

	}

	gsf_output_close(GSF_OUTPUT(outfile));
	gsf_shutdown ();
}

