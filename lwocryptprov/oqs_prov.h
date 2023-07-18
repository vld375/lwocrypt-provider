// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * Main lwocryptprovider header file
 *
 * Code strongly inspired by OpenSSL crypto/ecx key handler.
 *
 */

/* Internal LWOCRYPT functions for other submodules: not for application use */

#ifndef LWOCRYPTX_H
# define LWOCRYPTX_H

#ifndef LWOCRYPT_PROVIDER_NOATOMIC
# include <stdatomic.h>
#endif

# include <openssl/opensslconf.h>
# include <openssl/bio.h>

#  include <openssl/core.h>
#  include <openssl/e_os2.h>

#define LWOCRYPT_PROVIDER_VERSION_STR LWOCRYPTPROVIDER_VERSION_TEXT

/* internal, but useful OSSL define */
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

/* lwocryptprovider error codes */
#define LWOCRYPTPROV_R_INVALID_DIGEST                            1
#define LWOCRYPTPROV_R_INVALID_SIZE                              2
#define LWOCRYPTPROV_R_INVALID_KEY                               3
#define LWOCRYPTPROV_R_UNSUPPORTED                               4
#define LWOCRYPTPROV_R_MISSING_OID                               5 
#define LWOCRYPTPROV_R_OBJ_CREATE_ERR                            6
#define LWOCRYPTPROV_R_INVALID_ENCODING                          7
#define LWOCRYPTPROV_R_SIGN_ERROR				    8
#define LWOCRYPTPROV_R_LIB_CREATE_ERR			    9
#define LWOCRYPTPROV_R_NO_PRIVATE_KEY			    10
#define LWOCRYPTPROV_R_BUFFER_LENGTH_WRONG			    11
#define LWOCRYPTPROV_R_SIGNING_FAILED			    12
#define LWOCRYPTPROV_R_WRONG_PARAMETERS			    13
#define LWOCRYPTPROV_R_VERIFY_ERROR				    14
#define LWOCRYPTPROV_R_EVPINFO_MISSING			    15

/* Extras for LWOCRYPT extension */

// Helpers for (classic) key length storage
#define SIZE_OF_UINT32 4
#define ENCODE_UINT32(pbuf, i)  (pbuf)[0] = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[1] = (unsigned char)((i>>16) & 0xff); \
                                (pbuf)[2] = (unsigned char)((i>> 8) & 0xff); \
                                (pbuf)[3] = (unsigned char)((i    ) & 0xff)
#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) ((unsigned char*)pbuf)[0]) << 24; \
                                i |= ((uint32_t) ((unsigned char*)pbuf)[1]) << 16; \
                                i |= ((uint32_t) ((unsigned char*)pbuf)[2]) <<  8; \
                                i |= ((uint32_t) ((unsigned char*)pbuf)[3])


#define ON_ERR_SET_GOTO(condition, ret, code, gt) \
    if ((condition)) {                            \
        (ret) = (code);                           \
        goto gt;                                  \
    }

#define ON_ERR_GOTO(condition, gt) \
    if ((condition)) {                        \
        goto gt;                              \
    }

typedef struct prov_lwocrypt_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
    BIO_METHOD *corebiometh; 
} PROV_LWOCRYPT_CTX;

PROV_LWOCRYPT_CTX *lwocryptx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm);
void lwocryptx_freeprovctx(PROV_LWOCRYPT_CTX *ctx);
# define PROV_LWOCRYPT_LIBCTX_OF(provctx) (((PROV_LWOCRYPT_CTX *)provctx)->libctx)

#include "lwocrypt/lwocrypt.h"
#ifdef USE_ENCODING_LIB
#include <qsc_encoding.h>
#endif

/* helper structure for classic key components in hybrid keys.
 * Actual tables in lwocryptprov_keys.c
 */
struct lwocryptx_evp_info_st {
    int keytype;
    int nid;
    int raw_key_support;
    size_t length_public_key;
    size_t length_private_key;
    size_t kex_length_secret;
    size_t length_signature;
};

typedef struct lwocryptx_evp_info_st LWOCRYPTX_EVP_INFO;

struct lwocryptx_evp_ctx_st {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *keyParam;
    const LWOCRYPTX_EVP_INFO *evp_info;
};

typedef struct lwocryptx_evp_ctx_st LWOCRYPTX_EVP_CTX;

typedef union {
    LWOCRYPT_SIG *sig;
    LWOCRYPT_KEM *kem;
} LWOCRYPTX_QS_CTX;

struct lwocryptx_provider_ctx_st {
    LWOCRYPTX_QS_CTX lwocryptx_qs_ctx;
    LWOCRYPTX_EVP_CTX *lwocryptx_evp_ctx;
};

typedef struct lwocryptx_provider_ctx_st LWOCRYPTX_PROVIDER_CTX;

#ifdef USE_ENCODING_LIB
struct lwocryptx_provider_encoding_ctx_st {
    const qsc_encoding_t* encoding_ctx;
    const qsc_encoding_impl_t* encoding_impl;
};

typedef struct lwocryptx_provider_encoding_ctx_st LWOCRYPTX_ENCODING_CTX;
#endif

enum lwocryptx_key_type_en {
    KEY_TYPE_SIG, KEY_TYPE_KEM, KEY_TYPE_ECP_HYB_KEM, KEY_TYPE_ECX_HYB_KEM, KEY_TYPE_HYB_SIG
};

typedef enum lwocryptx_key_type_en LWOCRYPTX_KEY_TYPE;

struct lwocryptx_key_st {
    OSSL_LIB_CTX *libctx;
#ifdef LWOCRYPT_PROVIDER_NOATOMIC
    CRYPTO_RWLOCK *lock;
#endif
    char *propq;
    LWOCRYPTX_KEY_TYPE keytype;
    LWOCRYPTX_PROVIDER_CTX lwocryptx_provider_ctx;
#ifdef USE_ENCODING_LIB
    LWOCRYPTX_ENCODING_CTX lwocryptx_encoding_ctx;
#endif
    EVP_PKEY *classical_pkey; // for hybrid sigs
    const LWOCRYPTX_EVP_INFO *evp_info;
    size_t numkeys;

    /* key lengths including size fields for classic key length information: (numkeys-1)*SIZE_OF_UINT32
     */
    size_t privkeylen;
    size_t pubkeylen;
    size_t bit_security;
    char *tls_name;
#ifndef LWOCRYPT_PROVIDER_NOATOMIC
    _Atomic
#endif
            int references;

    /* point to actual priv key material -- classic key, if present, first
     * i.e., LWOCRYPT key always at comp_*key[numkeys-1]
     */
    void **comp_privkey;
    void **comp_pubkey;

    /* contain key material: First SIZE_OF_UINT32 bytes indicating actual classic 
     * key length in case of hybrid keys (if numkeys>1)
     */
    void *privkey;
    void *pubkey;
};

typedef struct lwocryptx_key_st LWOCRYPTX_KEY;

/* Register given NID with tlsname in OSSL3 registry */
int lwocrypt_set_nid(char* tlsname, int nid);

/* Create LWOCRYPTX_KEY data structure based on parameters; key material allocated separately */ 
LWOCRYPTX_KEY *lwocryptx_key_new(OSSL_LIB_CTX *libctx, char* lwocrypt_name, char* tls_name, int is_kem, const char *propq, int bit_security, int alg_idx);

/* allocate key material; component pointers need to be set separately */
int lwocryptx_key_allocate_keymaterial(LWOCRYPTX_KEY *key, int include_private);

/* free all data structures, incl. key material */
void lwocryptx_key_free(LWOCRYPTX_KEY *key);

/* increase reference count of given key */
int lwocryptx_key_up_ref(LWOCRYPTX_KEY *key);

/* do (composite) key generation */
int lwocryptx_key_gen(LWOCRYPTX_KEY *key);

/* create LWOCRYPTX_KEY from pkcs8 data structure */
LWOCRYPTX_KEY *lwocryptx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const char *propq);

/* create LWOCRYPTX_KEY (public key material only) from X509 data structure */
LWOCRYPTX_KEY *lwocryptx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx, const char *propq);

/* Backend support */
/* populate key material from parameters */
int lwocryptx_key_fromdata(LWOCRYPTX_KEY *lwocryptxk, const OSSL_PARAM params[],
                     int include_private);
/* retrieve security bit count for key */
int lwocryptx_key_secbits(LWOCRYPTX_KEY *k);
/* retrieve pure LWOCRYPT key len */
int lwocryptx_key_get_lwocrypt_public_key_len(LWOCRYPTX_KEY *k);
/* retrieve maximum size of generated artifact (shared secret or signature, respectively) */
int lwocryptx_key_maxsize(LWOCRYPTX_KEY *k);
void lwocryptx_key_set0_libctx(LWOCRYPTX_KEY *key, OSSL_LIB_CTX *libctx);
int lwocrypt_patch_codepoints(void);

/* Function prototypes */

extern const OSSL_DISPATCH lwocrypt_generic_kem_functions[];
extern const OSSL_DISPATCH lwocrypt_hybrid_kem_functions[];
extern const OSSL_DISPATCH lwocrypt_signature_functions[];

///// LWOCRYPT_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_START
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium2_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_dilithium2_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p256_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p256_dilithium2_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_rsa3072_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_rsa3072_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_dilithium3_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p384_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p384_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_dilithium5_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p521_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p521_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_falcon512_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_falcon512_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_falcon512_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p256_falcon512_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p256_falcon512_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_rsa3072_falcon512_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_rsa3072_falcon512_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_falcon1024_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_falcon1024_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p521_falcon1024_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p521_falcon1024_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_sphincssha2128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_sphincssha2128fsimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p256_sphincssha2128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p256_sphincssha2128fsimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_rsa3072_sphincssha2128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_rsa3072_sphincssha2128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_sphincssha2128ssimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_sphincssha2128ssimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p256_sphincssha2128ssimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p256_sphincssha2128ssimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_rsa3072_sphincssha2128ssimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_rsa3072_sphincssha2128ssimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_sphincssha2192fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_sphincssha2192fsimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p384_sphincssha2192fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p384_sphincssha2192fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_sphincsshake128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_sphincsshake128fsimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_p256_sphincsshake128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_p256_sphincsshake128fsimple_decoder_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_to_text_encoder_functions[];
extern const OSSL_DISPATCH lwocrypt_PrivateKeyInfo_der_to_rsa3072_sphincsshake128fsimple_decoder_functions[];
extern const OSSL_DISPATCH lwocrypt_SubjectPublicKeyInfo_der_to_rsa3072_sphincsshake128fsimple_decoder_functions[];
///// LWOCRYPT_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_END

///// LWOCRYPT_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH lwocrypt_dilithium2_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p256_dilithium2_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium3_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p384_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_dilithium5_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p521_dilithium5_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon512_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p256_falcon512_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_falcon512_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_falcon1024_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p521_falcon1024_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128fsimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128fsimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128fsimple_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2128ssimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincssha2128ssimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincssha2128ssimple_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincssha2192fsimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p384_sphincssha2192fsimple_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_sphincsshake128fsimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_p256_sphincsshake128fsimple_keymgmt_functions[];extern const OSSL_DISPATCH lwocrypt_rsa3072_sphincsshake128fsimple_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_frodo640aes_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p256_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_frodo640shake_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p256_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_frodo976aes_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p384_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x448_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_frodo976shake_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p384_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x448_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_frodo1344aes_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p521_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_frodo1344shake_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p521_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_kyber512_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p256_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_kyber768_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p384_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x448_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecp_p256_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_kyber1024_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p521_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_bikel1_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p256_bikel1_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_bikel1_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_bikel3_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p384_bikel3_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x448_bikel3_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_bikel5_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p521_bikel5_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_hqc128_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p256_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x25519_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_hqc192_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p384_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_ecx_x448_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH lwocrypt_hqc256_keymgmt_functions[];

extern const OSSL_DISPATCH lwocrypt_ecp_p521_hqc256_keymgmt_functions[];
///// LWOCRYPT_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_END

/* BIO function declarations */
int lwocrypt_prov_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *lwocrypt_prov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *lwocrypt_prov_bio_new_membuf(const char *filename, int len);
int lwocrypt_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int lwocrypt_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written);
int lwocrypt_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int lwocrypt_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int lwocrypt_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int lwocrypt_prov_bio_up_ref(OSSL_CORE_BIO *bio);
int lwocrypt_prov_bio_free(OSSL_CORE_BIO *bio);
int lwocrypt_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int lwocrypt_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *lwocrypt_bio_prov_init_bio_method(void);
BIO *lwocrypt_bio_new_from_core_bio(PROV_LWOCRYPT_CTX *provctx, OSSL_CORE_BIO *corebio);

#endif
