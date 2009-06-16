/*
 * KRB5_fmt.c
 *
 *  Kerberos 5 module for John the Ripper by Solar Designer, based on the 
 *  KRB4 module by Dug Soug.
 *
 * Author: Nasko Oskov <nasko@netsekure.org>
 *
 * Licensing:
 *   
 *  The module contains code derived or copied from the Heimdal project.
 *  
 *  Copyright (c) 1997-2000 Kungliga Tekniska H�gskolan 
 *  (Royal Institute of Technology, Stockholm, Sweden).
 *  All rights reserved.
 *
 *  Which is distribution of Kerberos based on M.I.T. implementation.
 *
 *  Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 */

#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <string.h>
#include <openssl/des.h>

#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "formats.h"    // needed for format structs
#include "KRB5_std.h"


// defines                                                  // {{{
#define MAGIC_PREFIX        "$krb5$"
#define MAX_REALM_LEN       64
#define TGT_SIZE            228
#define MAX_USER_LEN        64
#define MAX_PASS_LEN        64

#define FORMAT_LABEL        "krb5"
#define FORMAT_NAME         "Kerberos v5 TGT"
#define ALGORITHM_NAME      "krb5 3DES (des3-cbc-sha1)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#define DES3_KEY_SIZE           24
#define DES3_KEY_BITS           168
#define DES3_KEY_SCHED_SIZE     384

#define KRBTGT              "krbtgt"
// }}}


/**
 * structure to hold the self tests                             // {{{
 */
static struct fmt_tests    KRB5_fmt_tests[] = {
    {"$krb5$oskov$ACM.UIUC.EDU$4730d7249765615d6f3652321c4fb76d09fb9cd06faeb0c31b8737f9fdfcde4bd4259c31cb1dff25df39173b09abdff08373302d99ac09802a290915243d9f0ea0313fdedc7f8d1fae0d9df8f0ee6233818d317f03a72c2e77b480b2bc50d1ca14fba85133ea00e472c50dbc825291e2853bd60a969ddb69dae35b604b34ea2c2265a4ffc72e9fb811da17c7f2887ccb17e2f87cd1f6c28a9afc0c083a9356a9ee2a28d2e4a01fc7ea90cc8836b8e25650c3a1409b811d0bad42a59aa418143291d42d7b1e6cb5b1876a4cc758d721323a762e943f774630385c9faa68df6f3a94422f97", "p4ssW0rd"},
    {"$krb5$oskov$ACM.UIUC.EDU$6cba0316d38e31ba028f87394792baade516afdfd8c5a964b6a7677adbad7815d778b297beb238394aa97a4d495adb7c9b7298ba7c2a2062fb6c9a4297f12f83755060f4f58a1ea4c7026df585cdfa02372ad619ab1a4ec617ad23e76d6e37e36268d9aa0abcf83f11fa8092b4328c5e6c577f7ec6f1c1684d9c99a309eee1f5bd764c4158a2cf311cded8794b2de83131c3dc51303d5300e563a2b7a230eac67e85b4593e561bf6b88c77b82c729e7ba7f3d2f99b8dc85b07873e40335aff4647833a87681ee557fbd1ffa1a458a5673d1bd3c1587eceeabaebf4e44c24d9a8ac8c1d89", "Nask0Oskov"},
    {NULL}
};
// }}}

/**
 * struct to save the salt into
 */
struct salt {                                                       // {{{
    char    realm[MAX_REALM_LEN];
    char    user[MAX_USER_LEN];
    char    tgt_ebin[TGT_SIZE];
    char    passwd[MAX_PASS_LEN];
};
#define SALT_SIZE           sizeof(struct salt)
// }}}

struct key {                                                        // {{{
    char    passwd[MAX_PASS_LEN];
    char    key[MAX_PASS_LEN];
    DES_key_schedule sched[3];
};
// }}}

static struct salt *psalt = NULL;
static struct key skey;

static char username[MAX_USER_LEN];
static char realm[MAX_REALM_LEN];
static char password[MAX_PASS_LEN];

// initialization vector for des
static DES_cblock ivec;

krb5_key _krb5key;
krb5_key *krb5key = &_krb5key;

/**
 * hex2bin           // {{{
 */
static void hex2bin(char *src, u_char *dst, int outsize) {
    char *p, *pe;
    u_char *q, *qe, ch, cl;

    pe = src + strlen(src);
    qe = dst + outsize;

    for (p = src, q = dst; p < pe && q < qe && isxdigit((int)*p); p += 2) {
        ch = tolower(p[0]);
        cl = tolower(p[1]);

        if ((ch >= '0') && (ch <= '9')) ch -= '0';
        else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
        else return;

        if ((cl >= '0') && (cl <= '9')) cl -= '0';
        else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
        else return;

        *q++ = (ch << 4) | cl;
    }
}
// }}}

/**
 * krb5_decrypt_compare                                             // {{{
 *
 */
int krb5_decrypt_compare() {
    
    char plain[TGT_SIZE];
    int i;

    memset(krb5key->key, 0x00, DES3_KEY_SIZE);
    memset(krb5key->schedule, 0x00, DES3_KEY_SCHED_SIZE);

    memset(username, 0x00, MAX_USER_LEN);
    memcpy(username, psalt->user, strlen(psalt->user));
    memset(realm, 0x00, MAX_REALM_LEN);
    memcpy(realm, psalt->realm, strlen(psalt->realm));
    memset(password, 0x00, MAX_PASS_LEN);
    memcpy(password, skey.passwd, strlen(skey.passwd));

    // do str2key
    str2key(username, realm, password, krb5key);

    des3_decrypt(krb5key, psalt->tgt_ebin, plain, TGT_SIZE);

    for(i=0;i<TGT_SIZE;++i)
        if (plain[i] == 'k')
            if (strncmp(plain + i, KRBTGT, strlen(KRBTGT)) == 0) {
                memset(psalt->passwd, 0x00, MAX_PASS_LEN);
                strncpy(psalt->passwd, skey.passwd, strlen(skey.passwd));
                return 1;
            }
    return 0;
}
// }}}

/**
 * int krb5_valid                                                   // {{{
 * 
 */
static int krb5_valid(char *ciphertext) {       
    
    if (strncmp(ciphertext, MAGIC_PREFIX, strlen(MAGIC_PREFIX)) != 0)
        return 0;
    
    return 1;
}
// }}}

/**
 * void * krb5_salt                                                 // {{{
 * 
 */
static void * krb5_salt(char *ciphertext) {
    
    struct salt *salt = NULL;
    char *data = ciphertext, *p;
    
    // check the presence of $krb5$
    if (strncmp(data, MAGIC_PREFIX, strlen(MAGIC_PREFIX)) == 0) {
        // advance past the $krb5$ string
        data += strlen(MAGIC_PREFIX);

        // allocate memory for the struct
        salt = malloc(sizeof(struct salt));
        if (salt == NULL)
            return NULL;

        // find and copy the user field 
        p = strchr(data, '$');
        strnzcpy(salt->user, data, (p - data) + 1);
        data = p + 1;
        
        // find and copy the realm field 
        p = strchr(data, '$');
        strnzcpy(salt->realm, data, (p - data) + 1);
        data = p + 1;
        
        // copy over the TGT in a binary form to the salt struct
        hex2bin(data, (u_char *) salt->tgt_ebin, TGT_SIZE);        
    }
    return salt;
}
// }}}

/**
 * void krb5_set_salt                                               // {{{
 *
 */
static void krb5_set_salt(void *salt) {   
    psalt = (struct salt *) salt;    
}
// }}}

/**
 * void krb5_set_key                                                // {{{
 * 
 */
static void krb5_set_key(char *key, int index) {   

    // copy the string key to the saved key
    memset(skey.passwd, 0x00, MAX_PASS_LEN);
    strnzcpy(skey.passwd, key, sizeof(skey.passwd));

}
// }}}

/**
 * char * krb5_get_key                                              // {{{
 * 
 */
static char * krb5_get_key(int index) {   
    return skey.passwd;
}
// }}}

/** 
 * void krb5_crypt_all                                              // {{{
 * 
 */
static void krb5_crypt_all(int count) {   
    // do nothing
}
// }}}

/**
 * int krb5_cmp_all                                                 // {{{
 * 
 */
static inline int krb5_cmp_all(void *binary, int count) {

    return krb5_decrypt_compare();

}
// }}}

/**
 * int krb5_cmp_one                                                 // {{{
 *
 */
static int krb5_cmp_one(void *binary, int count) {

    return krb5_decrypt_compare();

}
// }}}

/**
 * int krb5_cmp_exact                                               // {{{
 * 
 */
static int krb5_cmp_exact(char *source, int index) {   
    return 1;
}
// }}}

/**
 * void krb5_init                                                   // {{{
 *
 */
static void krb5_init() {
    
    memset(&ivec, 0x00, sizeof(ivec));
    memset(&skey, 0x00, sizeof(skey));
    memset(krb5key, 0x00, sizeof(krb5_key));
    
    krb5key->key = (char *) malloc(DES3_KEY_SIZE);
    krb5key->schedule = (char *) malloc(DES3_KEY_SCHED_SIZE);
    memset(krb5key->key, 0x00, DES3_KEY_SIZE);
    memset(krb5key->schedule, 0x00, DES3_KEY_SCHED_SIZE);
    
}
// }}}

/**
 * fmt_main struct with KRB5 values                                     // {{{
 */
struct fmt_main fmt_KRB5 = {
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
        KRB5_fmt_tests
    }, {
        krb5_init,
        krb5_valid,
        fmt_default_split,
        fmt_default_binary,
        krb5_salt,  
        {   
            fmt_default_binary_hash,
            fmt_default_binary_hash,
            fmt_default_binary_hash
        },
        fmt_default_salt_hash,
        krb5_set_salt,
        krb5_set_key,
        krb5_get_key,
	    fmt_default_clear_keys,
        krb5_crypt_all,
        {   
            fmt_default_get_hash,
            fmt_default_get_hash,
            fmt_default_get_hash
        }, 
        krb5_cmp_all,
        krb5_cmp_one,
        krb5_cmp_exact
    }   
};  
// }}}

