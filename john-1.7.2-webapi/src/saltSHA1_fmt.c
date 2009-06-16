/*
 * Copyright (c) 2006 dr_springfield
 * braden127@myrealbox.com
 * (with further changes by others for the jumbo patch)
 *
 * Simple Salt sha1 cracker
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "sha_locl.h"

#define FORMAT_LABEL			"macosx-sha1"
#define FORMAT_NAME			"Salt SHA1 - MacOSX"
#define ALGORITHM_NAME			"salt-sha1"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		48

#define BINARY_SIZE			20
#define SALT_SIZE			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests saltsha1_tests[] = {
	{"12345678f9083c7f66f46a0a102e4cc17ec08c8af120571b", "abc"},
	{"12345678eb8844bfaf2a8cbdd587a37ef8d4a290680d5818", "azertyuiop1"},
	{"3234c32aaa335fd20e3f95870e5851bdbe942b79ce4fdd92", "azertyuiop2"},
	{"123456783132e627074cbc7d637a219b368d2d38676943e0", "azertyuiop3"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_length;
static ARCH_WORD_32 saved_salt;
static SHA_CTX ctx;
static ARCH_WORD_32 crypt_out[5];

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD_32 salt;

	sscanf(ciphertext, "%08X", &salt);
#if ARCH_LITTLE_ENDIAN
	Endian_Reverse32(salt);
#endif

	return &salt;
}

static void saltsha1_set_salt(void *salt)
{
	saved_salt = *(ARCH_WORD_32 *)salt;
}

static void saltsha1_set_key(char *key, int index) {
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
}

static char *saltsha1_get_key(int index) {
	return saved_key;
}

static int saltsha1_cmp_all(void *binary, int index) {
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int saltsha1_cmp_exact(char *source, int count) {
	return 1;
}

static void saltsha1_crypt_all(int count) {
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (void*)&saved_salt, SALT_SIZE );
	SHA1_Update( &ctx, (unsigned char *) saved_key, saved_key_length );
	SHA1_Final( (unsigned char*) crypt_out, &ctx);
}

static void * saltsha1_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];

	int i;	
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+8])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+9])];
	
	return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int get_hash_0(int index)
{
  return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
  return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
  return crypt_out[0] & 0xFFF;
}

struct fmt_main fmt_saltSHA1 = {
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
		saltsha1_tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		saltsha1_binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2
		},
		fmt_default_salt_hash,
		saltsha1_set_salt,
		saltsha1_set_key,
		saltsha1_get_key,
		fmt_default_clear_keys,
		saltsha1_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2
		},
		saltsha1_cmp_all,
		saltsha1_cmp_all,
		saltsha1_cmp_exact
	}
};
