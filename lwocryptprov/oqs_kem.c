// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * LWOCRYPT OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 * 
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>
#include "lwocrypt_prov.h"

#ifdef NDEBUG
#define LWOCRYPT_KEM_PRINTF(a)
#define LWOCRYPT_KEM_PRINTF2(a, b)
#define LWOCRYPT_KEM_PRINTF3(a, b, c)
#else
#define LWOCRYPT_KEM_PRINTF(a) if (getenv("LWOCRYPTKEM")) printf(a)
#define LWOCRYPT_KEM_PRINTF2(a, b) if (getenv("LWOCRYPTKEM")) printf(a, b)
#define LWOCRYPT_KEM_PRINTF3(a, b, c) if (getenv("LWOCRYPTKEM")) printf(a, b, c)
#endif // NDEBUG


static OSSL_FUNC_kem_newctx_fn lwocrypt_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn lwocrypt_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn lwocrypt_qs_kem_encaps;
static OSSL_FUNC_kem_encapsulate_fn lwocrypt_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn lwocrypt_qs_kem_decaps;
static OSSL_FUNC_kem_decapsulate_fn lwocrypt_hyb_kem_decaps;
static OSSL_FUNC_kem_freectx_fn lwocrypt_kem_freectx;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    LWOCRYPTX_KEY *kem;
} PROV_LWOCRYPTKEM_CTX;

/// Common KEM functions

static void *lwocrypt_kem_newctx(void *provctx)
{
    PROV_LWOCRYPTKEM_CTX *pkemctx =  OPENSSL_zalloc(sizeof(PROV_LWOCRYPTKEM_CTX));

    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_LWOCRYPT_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void lwocrypt_kem_freectx(void *vpkemctx)
{
    PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;

    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: freectx\n");
    lwocryptx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int lwocrypt_kem_decapsencaps_init(void *vpkemctx, void *vkem, int operation)
{
    PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;

    LWOCRYPT_KEM_PRINTF3("LWOCRYPT KEM provider called: _init : New: %p; old: %p \n", vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !lwocryptx_key_up_ref(vkem)) 
        return 0;
    lwocryptx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int lwocrypt_kem_encaps_init(void *vpkemctx, void *vkem, const OSSL_PARAM params[])
{
    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: encaps_init\n");
    return lwocrypt_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int lwocrypt_kem_decaps_init(void *vpkemctx, void *vkem, const OSSL_PARAM params[])
{
    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: decaps_init\n");
    return lwocrypt_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

/// Quantum-Safe KEM functions (LWOCRYPT)

static int lwocrypt_qs_kem_encaps_keyslot(void *vpkemctx, unsigned char *out, size_t *outlen,
                                     unsigned char *secret, size_t *secretlen, int keyslot)
{
    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    const LWOCRYPT_KEM *kem_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem;

    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: encaps\n");
    if (pkemctx->kem == NULL) {
        LWOCRYPT_KEM_PRINTF("LWOCRYPT Warning: LWOCRYPT_KEM not initialized\n");
        return -1;
    }
    *outlen = kem_ctx->length_ciphertext;
    *secretlen = kem_ctx->length_shared_secret;
    if (out == NULL || secret == NULL) {
       LWOCRYPT_KEM_PRINTF3("KEM returning lengths %ld and %ld\n", *outlen, *secretlen);
       return 1;
    }
    return LWOCRYPT_SUCCESS == LWOCRYPT_KEM_encaps(kem_ctx, out, secret, pkemctx->kem->comp_pubkey[keyslot]);
}

static int lwocrypt_qs_kem_decaps_keyslot(void *vpkemctx, unsigned char *out, size_t *outlen,
                                     const unsigned char *in, size_t inlen, int keyslot)
{
    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    const LWOCRYPT_KEM *kem_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem;

    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: decaps\n");
    if (pkemctx->kem == NULL) {
        LWOCRYPT_KEM_PRINTF("LWOCRYPT Warning: LWOCRYPT_KEM not initialized\n");
        return -1;
    }
    *outlen = kem_ctx->length_shared_secret;
    if (out == NULL) return 1;

    return LWOCRYPT_SUCCESS == LWOCRYPT_KEM_decaps(kem_ctx, out, in, pkemctx->kem->comp_privkey[keyslot]);
}

static int lwocrypt_qs_kem_encaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen)
{
    return lwocrypt_qs_kem_encaps_keyslot(vpkemctx, out, outlen, secret, secretlen, 0);
}

static int lwocrypt_qs_kem_decaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    return lwocrypt_qs_kem_decaps_keyslot(vpkemctx, out, outlen, in, inlen, 0);
}

/// EVP KEM functions

static int lwocrypt_evp_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                                      unsigned char *secret, size_t *secretlen, int keyslot)
{
    int ret = LWOCRYPT_SUCCESS, ret2 = 0;

    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    const LWOCRYPTX_EVP_CTX *evp_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_evp_ctx;

    size_t pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0;
    unsigned char *pubkey_kex = pkemctx->kem->comp_pubkey[keyslot];

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL, *kgctx = NULL;;
    EVP_PKEY *pkey = NULL, *peerpk = NULL;
    unsigned char *ctkex_encoded = NULL;

    pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    kexDeriveLen = evp_ctx->evp_info->kex_length_secret;

    *ctlen = pubkey_kexlen;
    *secretlen = kexDeriveLen;

    if (ct == NULL || secret == NULL) {
        LWOCRYPT_KEM_PRINTF3("EVP KEM returning lengths %ld and %ld\n", *ctlen, *secretlen);
        return 1;
    }

    peerpk = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpk, ret, -1, err);

    ret2 = EVP_PKEY_copy_parameters(peerpk, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpk, pubkey_kex, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    kgctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, err);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive_set_peer(ctx, peerpk);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    pkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &ctkex_encoded);
    ON_ERR_SET_GOTO(pkeylen <= 0 || !ctkex_encoded || pkeylen != pubkey_kexlen, ret, -1, err);

    memcpy(ct, ctkex_encoded, pkeylen);

    err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerpk);
    OPENSSL_free(ctkex_encoded);
    return ret;
}

static int lwocrypt_evp_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret, size_t *secretlen,
                                      const unsigned char *ct, size_t ctlen, int keyslot)
{
    LWOCRYPT_KEM_PRINTF("LWOCRYPT KEM provider called: lwocrypt_hyb_kem_decaps\n");

    int ret = LWOCRYPT_SUCCESS, ret2 = 0;
    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    const LWOCRYPTX_EVP_CTX *evp_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_evp_ctx;

    size_t pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    size_t kexDeriveLen = evp_ctx->evp_info->kex_length_secret;
    unsigned char *privkey_kex = pkemctx->kem->comp_privkey[keyslot];
    size_t privkey_kexlen = evp_ctx->evp_info->length_private_key;

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;

    *secretlen = kexDeriveLen;
    if (secret == NULL) return 1;

    if (evp_ctx->evp_info->raw_key_support) {
        pkey = EVP_PKEY_new_raw_private_key(evp_ctx->evp_info->keytype, NULL, privkey_kex, privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -10, err);
    } else {
        pkey = d2i_AutoPrivateKey(&pkey, (const unsigned char **)&privkey_kex, privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -2, err);
    }

    peerpkey = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpkey, ret, -3, err);

    ret2 = EVP_PKEY_copy_parameters(peerpkey, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -4, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpkey, ct, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0 || !peerpkey, ret, -5, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -6, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -7, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpkey);
    ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -9, err);

    err:
    EVP_PKEY_free(peerpkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/// Hybrid KEM functions

static int lwocrypt_hyb_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen)
{
    int ret = LWOCRYPT_SUCCESS;
    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    unsigned char *ct0, *ct1, *secret0, *secret1;

    ret = lwocrypt_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLen0, NULL, &secretLen0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);
    ret = lwocrypt_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLen1, NULL, &secretLen1, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);


    *ctlen = ctLen0 + ctLen1;
    *secretlen = secretLen0 + secretLen1;

    if (ct == NULL || secret == NULL) {
        LWOCRYPT_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen, *secretlen);
        return 1;
    }

    ct0 = ct;
    ct1 = ct + ctLen0;
    secret0 = secret;
    secret1 = secret + secretLen0;

    ret = lwocrypt_evp_kem_encaps_keyslot(vpkemctx, ct0, &ctLen0, secret0, &secretLen0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);

    ret = lwocrypt_qs_kem_encaps_keyslot(vpkemctx, ct1, &ctLen1, secret1, &secretLen1, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);

    err:
    return ret;
}

static int lwocrypt_hyb_kem_decaps(void *vpkemctx, unsigned char *secret, size_t *secretlen,
                              const unsigned char *ct, size_t ctlen)
{
    int ret = LWOCRYPT_SUCCESS;
    const PROV_LWOCRYPTKEM_CTX *pkemctx = (PROV_LWOCRYPTKEM_CTX *)vpkemctx;
    const LWOCRYPTX_EVP_CTX *evp_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_evp_ctx;
    const LWOCRYPT_KEM *qs_ctx = pkemctx->kem->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem;

    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    const unsigned char *ct0, *ct1;
    unsigned char *secret0, *secret1;

    ret = lwocrypt_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLen0, NULL, 0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);
    ret = lwocrypt_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLen1, NULL, 0, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);

    *secretlen = secretLen0 + secretLen1;

    if (secret == NULL) return 1;

    ctLen0 = evp_ctx->evp_info->length_public_key;
    ctLen1 = qs_ctx->length_ciphertext;

    ON_ERR_SET_GOTO(ctLen0 + ctLen1 != ctlen, ret, LWOCRYPT_ERROR, err);

    ct0 = ct;
    ct1 = ct + ctLen0;
    secret0 = secret;
    secret1 = secret + secretLen0;

    ret = lwocrypt_evp_kem_decaps_keyslot(vpkemctx, secret0, &secretLen0, ct0, ctLen0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);
    ret = lwocrypt_qs_kem_decaps_keyslot(vpkemctx, secret1, &secretLen1, ct1, ctLen1, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, LWOCRYPT_ERROR, err);

    err:
    return ret;
}

#define MAKE_KEM_FUNCTIONS(alg) \
    const OSSL_DISPATCH lwocrypt_##alg##_kem_functions[] = { \
      { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))lwocrypt_kem_newctx }, \
      { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))lwocrypt_kem_encaps_init }, \
      { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))lwocrypt_qs_kem_encaps }, \
      { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))lwocrypt_kem_decaps_init }, \
      { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))lwocrypt_qs_kem_decaps }, \
      { OSSL_FUNC_KEM_FREECTX, (void (*)(void))lwocrypt_kem_freectx }, \
      { 0, NULL } \
  };

#define MAKE_HYB_KEM_FUNCTIONS(alg) \
    const OSSL_DISPATCH lwocrypt_##alg##_kem_functions[] = { \
      { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))lwocrypt_kem_newctx }, \
      { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))lwocrypt_kem_encaps_init }, \
      { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))lwocrypt_hyb_kem_encaps }, \
      { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))lwocrypt_kem_decaps_init }, \
      { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))lwocrypt_hyb_kem_decaps }, \
      { OSSL_FUNC_KEM_FREECTX, (void (*)(void))lwocrypt_kem_freectx }, \
      { 0, NULL } \
  };

// keep this just in case we need to become ALG-specific at some point in time
MAKE_KEM_FUNCTIONS(generic)
MAKE_HYB_KEM_FUNCTIONS(hybrid)
