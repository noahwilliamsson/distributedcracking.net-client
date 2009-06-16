/*
 * Copyright (c) 2004 bartavelle
 * bartavelle@bandecon.com
 *
 * Simple MD5 hashes cracker
 * It uses the Solar Designer's md5 implementation
 * 
 * Minor changes by David Luyer <david@luyer.net> to
 * use a modified (faster) version of Solar Designer's
 * md5 implementation.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5_go.h"

#if !ARCH_LITTLE_ENDIAN
#define MD5_out MD5_bitswapped_out
#endif

extern ARCH_WORD_32 MD5_out[4];

#define FORMAT_LABEL			"raw-md5"
#define FORMAT_NAME			"Raw MD5"
#define ALGORITHM_NAME			"raw-md5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests rawmd5_tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"ad0234829205b9033196ba818f7a872b", "test2"},
	{"8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"86985e105f79b95d6bc918fb45ec7727", "test4"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1 + 128 /* MD5 scratch space */];
int saved_key_len;

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  ))
			return 0;
	}
	return 1;
}

static void rawmd5_set_salt(void *salt) { }

static void rawmd5_set_key(char *key, int index) {
    strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
    saved_key_len = strlen(saved_key);
}

static char *rawmd5_get_key(int index) {
    saved_key[saved_key_len] = '\0';
    return saved_key;
}

static int rawmd5_cmp_all(void *binary, int index) {
    /* used for cmp_all and cmp_one */
    return !memcmp(binary, MD5_out, BINARY_SIZE);
}

static int rawmd5_cmp_exact(char *source, int count){
    /* only used if cmp_all matches */
    return (1);
}

static void rawmd5_crypt_all(int count) {  
    /* get plaintext input in saved_key put it into ciphertext MD5_out */
    MD5_Go( (unsigned char *)saved_key, saved_key_len );
}

static void * rawmd5_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

struct fmt_main fmt_rawMD5go = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		rawmd5_tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		rawmd5_binary,
		fmt_default_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		rawmd5_set_salt,
		rawmd5_set_key,
		rawmd5_get_key,
		fmt_default_clear_keys,
		rawmd5_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		rawmd5_cmp_all,
		rawmd5_cmp_all,
		rawmd5_cmp_exact
	}
};
