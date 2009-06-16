// Fix for john the ripper 1.6.37 by Sun-Zero, 2004. 07. 26.
/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Minor performance enhancement by bartavelle@bandecon.com
 */

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "common.h"

#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"ssha"
#define FORMAT_NAME			"Netscape LDAP SSHA"
#define SHA_TYPE                        "salted SHA1"

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			8

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) )	
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

static struct fmt_tests tests[] = {
  {"{SSHA}ypkVeJKLzbXakEpuPYbn+YBnQvFmNmB+kQhmWQ==", "qVv3uQ45"},
  {"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
  {"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
  {NULL}
};

#ifdef MMX_COEF
static char crypt_key[BINARY_SIZE*MMX_COEF];
static char saved_key[80*MMX_COEF];
static unsigned long total_len;
static unsigned char buffer[80*4*MMX_COEF] __attribute__ ((aligned(8*MMX_COEF)));
static unsigned char out[PLAINTEXT_LENGTH];
#else
static char crypt_key[BINARY_SIZE];
static char saved_key[PLAINTEXT_LENGTH + 1];
#endif

#ifdef MMX_COEF
static unsigned long length[MAX_KEYS_PER_CRYPT];
#endif
static char saved_salt[SALT_SIZE];

static void * binary(char *ciphertext) {
  static char realcipher[BINARY_SIZE + SALT_SIZE + 9];

  /* stupid overflows */
  memset(realcipher, 0, sizeof(realcipher));
  base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
  return (void *)realcipher;
}

static void * get_salt(char * ciphertext)
{
	static char realcipher[BINARY_SIZE + SALT_SIZE + 9];
	memset(realcipher, 0, sizeof(realcipher));
	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
	return (void*)realcipher+BINARY_SIZE;
}

static int valid(char *ciphertext)
{
	if(ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH + NSLDAP_MAGIC_LENGTH)
		return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
	return 0;
}

static int binary_hash_0(void *binary)
{
  return ((int *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
  return ((int *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
  return ((int *)binary)[0] & 0xFFF;
}

static int get_hash_0(int index)
{
  return ((int *)crypt_key)[index] & 0xF;
}

static int get_hash_1(int index)
{
  return ((int *)crypt_key)[index] & 0xFF;
}

static int get_hash_2(int index)
{
  return ((int *)crypt_key)[index] & 0xFFF;
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, sizeof(saved_key));
		memset(length, 0, sizeof(length));
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	length[index] = len;

	total_len += (len + SALT_SIZE) << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS( (i+SALT_SIZE) , index)] = 0x80;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static void set_salt(void *salt) 
{
	memcpy(saved_salt, salt, SALT_SIZE);
		
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int i,s;
	
	s = length[index];
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
  return saved_key;
#endif
}

static int 
cmp_all(void *binary, int index)
{
	int i = 0;
#ifdef MMX_COEF
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#endif
		)
			return 0;
		i++;
	}
#else
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int 
cmp_exact(char *source, int index)
{
  return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}


static void crypt_all(int count) 
{  
#ifdef MMX_COEF
	int i,idx;

	for(idx=0;idx<MAX_KEYS_PER_CRYPT;idx++)
		for(i=0;i<SALT_SIZE;i++)
		{
			saved_key[GETPOS(i+length[idx],idx)] = ((unsigned char *)saved_salt)[i];
		}
	memcpy(buffer, saved_key, 32*MMX_COEF);
	shammx((unsigned char *) crypt_key, buffer, total_len);
#else
	static SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *) saved_key, strlen(saved_key));
	SHA1_Update(&ctx, (unsigned char *) saved_salt, SALT_SIZE);
	SHA1_Final((unsigned char *) crypt_key, &ctx);
#endif
}

struct fmt_main fmt_NSLDAPS = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		SHA_TYPE,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all, 
		{
			get_hash_0,
			get_hash_1,
			get_hash_2
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

