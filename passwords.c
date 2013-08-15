#include "solar-md5/md5.h"
#include <string.h>
#include <stdint.h>

void print_hex (uint8_t *array, int n)
{
        int i;

        for (i = 0; i < n; i++) {
                printf ("%02x ", array[i]);
        }
        printf ("\n");
}

/* Convert a password entered by someone editing a document to the 5-byte
 * password used for encryption.
 * user_pass and salt are UTF-16 strings. Output is placed in real_key.
 * See http://msdn.microsoft.com/en-us/library/dd920360(v=office.12).aspx */

void convert_user_password(
		uint8_t real_key[5], uint8_t *user_pass, uint8_t salt[16])
{
	MD5_CTX md5_ctx;
	unsigned char md5_result[16];

	unsigned char intermediate[336];
	int i;
	print_hex (user_pass, 10);

	/* Take md5 hash of user_pass */
	MD5_Init (&md5_ctx);
	MD5_Update (&md5_ctx, user_pass, 10); /* 10 is length of 4qwer in utf16*/
	MD5_Final (md5_result, &md5_ctx);

	print_hex (md5_result, 16);

	/* Truncuate first 5 bytes and append salt */
	memmove (intermediate, md5_result, 5);
	memmove (intermediate + 5, salt, 16);

	/* Copy 16 times */
	for (i = 1; i < 16; i++) {
		memmove (intermediate + 21*i, intermediate, 21);
	}


	/* Take md5 hash */
	MD5_Init (&md5_ctx);
	MD5_Update (&md5_ctx, intermediate, 336);
	MD5_Final (md5_result, &md5_ctx);

	/* Take first 5 bytes */
	memmove (real_key, md5_result, 5);
}

main ()
{
	/* "4qwer" in UTF-16 */
	uint8_t *test_pass = "4\0q\0w\0e\0r\0";

	uint8_t salt[16] =
	{
		0x87, 0xc3, 0xc6, 0x72, 0x71, 0xe7, 0x3f, 0x99,
	       	0x31, 0x57, 0x80, 0x50, 0xa4, 0x7d, 0xc8, 0xfc 
	};

	uint8_t real_key[5];

	convert_user_password (real_key, test_pass, salt);

	print_hex (real_key, 5);
}
