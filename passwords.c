#include "solar-md5/md5.h"
#include <string.h>
#include <stdint.h>

/* Convert a password entered by someone editing a document to the 5-byte
 * password used for encryption.
 * user_pass and salt are UTF-16 strings. Output is placed in real_key.
 * See http://msdn.microsoft.com/en-us/library/dd920360(v=office.12).aspx */

void convert_user_password(
		 const uint8_t real_key[5],
		 uint8_t *user_pass, int len, uint8_t salt[16])
{
	MD5_CTX md5_ctx;
	unsigned char md5_result[16];

	unsigned char intermediate[336];
	int i;
	print_hex (user_pass, 10);

	/* Take md5 hash of user_pass */
	MD5_Init (&md5_ctx);
	MD5_Update (&md5_ctx, user_pass, len);
	MD5_Final (md5_result, &md5_ctx);

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
