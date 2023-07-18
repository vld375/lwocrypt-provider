// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * LWOCRYPT OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL DSA signature provider.
 * 
 */

#include "lwocrypt/sig.h"

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "lwocrypt_prov.h"

// TBD: Review what we really need/want: For now go with OSSL settings:
#define OSSL_MAX_NAME_SIZE 50
#define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */

#ifdef NDEBUG
#define LWOCRYPT_SIG_PRINTF(a)
#define LWOCRYPT_SIG_PRINTF2(a, b)
#define LWOCRYPT_SIG_PRINTF3(a, b, c)
#else
#define LWOCRYPT_SIG_PRINTF(a) if (getenv("LWOCRYPTSIG")) printf(a)
#define LWOCRYPT_SIG_PRINTF2(a, b) if (getenv("LWOCRYPTSIG")) printf(a, b)
#define LWOCRYPT_SIG_PRINTF3(a, b, c) if (getenv("LWOCRYPTSIG")) printf(a, b, c)
#endif // NDEBUG

static OSSL_FUNC_signature_newctx_fn lwocrypt_sig_newctx;
static OSSL_FUNC_signature_sign_init_fn lwocrypt_sig_sign_init;
static OSSL_FUNC_signature_verify_init_fn lwocrypt_sig_verify_init;
static OSSL_FUNC_signature_sign_fn lwocrypt_sig_sign;
static OSSL_FUNC_signature_verify_fn lwocrypt_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn lwocrypt_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn lwocrypt_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn lwocrypt_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn lwocrypt_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn lwocrypt_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn lwocrypt_sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn lwocrypt_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn lwocrypt_sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn lwocrypt_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn lwocrypt_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn lwocrypt_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn lwocrypt_sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn lwocrypt_sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn lwocrypt_sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn lwocrypt_sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn lwocrypt_sig_settable_ctx_md_params;

// OIDS:
static int get_aid(unsigned char** oidbuf, const char *tls_name) {
   X509_ALGOR *algor = X509_ALGOR_new();
   int aidlen = 0;

   X509_ALGOR_set0(algor, OBJ_txt2obj(tls_name, 0), V_ASN1_UNDEF, NULL);

   aidlen = i2d_X509_ALGOR(algor, oidbuf); 
   X509_ALGOR_free(algor);
   return(aidlen);
}

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    LWOCRYPTX_KEY *sig;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;
    // for collecting data if no MD is active:
    unsigned char* mddata;
    int operation;
} PROV_LWOCRYPTSIG_CTX;

static void *lwocrypt_sig_newctx(void *provctx, const char *propq)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: newctx called with propq %s\n", propq);

    plwocrypt_sigctx = OPENSSL_zalloc(sizeof(PROV_LWOCRYPTSIG_CTX));
    if (plwocrypt_sigctx == NULL)
        return NULL;

    plwocrypt_sigctx->libctx = ((PROV_LWOCRYPT_CTX*)provctx)->libctx;
    if (propq != NULL && (plwocrypt_sigctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(plwocrypt_sigctx);
        plwocrypt_sigctx = NULL;
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    }
    return plwocrypt_sigctx;
}

static int lwocrypt_sig_setup_md(PROV_LWOCRYPTSIG_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    LWOCRYPT_SIG_PRINTF3("LWOCRYPT SIG provider: setup_md called for MD %s (alg %s)\n", mdname, ctx->sig->tls_name);
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);

        if ((md == NULL)||(EVP_MD_nid(md)==NID_undef)) {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_CTX_free(ctx->mdctx);
	ctx->mdctx = NULL;
        EVP_MD_free(ctx->md);
	ctx->md = NULL;

        if (ctx->aid) 
            OPENSSL_free(ctx->aid);
        ctx->aid = NULL; // ensure next function allocates memory
        ctx->aid_len = get_aid(&(ctx->aid), ctx->sig->tls_name);

        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }
    return 1;
}

static int lwocrypt_sig_signverify_init(void *vplwocrypt_sigctx, void *vlwocryptsig, int operation)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: signverify_init called\n");
    if ( plwocrypt_sigctx == NULL
            || vlwocryptsig == NULL
            || !lwocryptx_key_up_ref(vlwocryptsig))
        return 0;
    lwocryptx_key_free(plwocrypt_sigctx->sig);
    plwocrypt_sigctx->sig = vlwocryptsig;
    plwocrypt_sigctx->operation = operation;
    plwocrypt_sigctx->flag_allow_md = 1; /* change permitted until first use */
    if ( (operation==EVP_PKEY_OP_SIGN && !plwocrypt_sigctx->sig->privkey) ||
         (operation==EVP_PKEY_OP_VERIFY && !plwocrypt_sigctx->sig->pubkey)) {
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_KEY);
        return 0;
    }
    return 1;
}

static int lwocrypt_sig_sign_init(void *vplwocrypt_sigctx, void *vlwocryptsig, const OSSL_PARAM params[])
{
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: sign_init called\n");
    return lwocrypt_sig_signverify_init(vplwocrypt_sigctx, vlwocryptsig, EVP_PKEY_OP_SIGN);
}

static int lwocrypt_sig_verify_init(void *vplwocrypt_sigctx, void *vlwocryptsig, const OSSL_PARAM params[])
{
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: verify_init called\n");
    return lwocrypt_sig_signverify_init(vplwocrypt_sigctx, vlwocryptsig, EVP_PKEY_OP_VERIFY);
}

/* On entry to this function, data to be signed (tbs) might have been hashed already:
 * this would be the case if plwocrypt_sigctx->mdctx != NULL; if that is NULL, we have to hash
 * in case of hybrid signatures
 */
static int lwocrypt_sig_sign(void *vplwocrypt_sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    LWOCRYPTX_KEY* lwocryptxkey = plwocrypt_sigctx->sig;
    LWOCRYPT_SIG*  lwocrypt_key = plwocrypt_sigctx->sig->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig;
    EVP_PKEY* evpkey = lwocryptxkey->classical_pkey; // if this value is not NULL, we're running hybrid
    EVP_PKEY_CTX *classical_ctx_sign = NULL;

    LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: sign called for %ld bytes\n", tbslen);

    int is_hybrid = evpkey!=NULL;
    size_t max_sig_len = lwocrypt_key->length_signature;
    size_t classical_sig_len = 0, lwocrypt_sig_len = 0;
    size_t actual_classical_sig_len = 0;
    size_t index = 0;
    int rv = 0;

    if (!lwocryptxkey || !lwocrypt_key || !lwocryptxkey->privkey) {
      ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_NO_PRIVATE_KEY);
      return rv;
    }
    if (is_hybrid) {
      actual_classical_sig_len = lwocryptxkey->evp_info->length_signature;
      max_sig_len += (SIZE_OF_UINT32 + actual_classical_sig_len);
    }

    if (sig == NULL) {
      *siglen = max_sig_len;
      LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: sign test returning size %ld\n", *siglen);
      return 1;
    }
    if (*siglen < max_sig_len) {
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_BUFFER_LENGTH_WRONG);
        return rv;
    }

    if (is_hybrid) {
        if ((classical_ctx_sign = EVP_PKEY_CTX_new(evpkey, NULL)) == NULL ||
            EVP_PKEY_sign_init(classical_ctx_sign) <= 0) {
          ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
          goto endsign;
        }
        if (lwocryptxkey->evp_info->keytype == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign, RSA_PKCS1_PADDING) <= 0) {
               ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
               goto endsign;
            }
        }

	/* unconditionally hash to be in line with lwocrypt-openssl111:
         * uncomment the following line if using pre-performed hash:
	 * if (plwocrypt_sigctx->mdctx == NULL) { // hashing not yet done
         */
          const EVP_MD *classical_md;
          int digest_len;
          unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

          /* classical schemes can't sign arbitrarily large data; we hash it first */
          switch (lwocrypt_key->claimed_nist_level) {
          case 1:
            classical_md = EVP_sha256();
            digest_len = SHA256_DIGEST_LENGTH;
            SHA256(tbs, tbslen, (unsigned char*) &digest);
            break;
          case 2:
          case 3:
            classical_md = EVP_sha384();
            digest_len = SHA384_DIGEST_LENGTH;
            SHA384(tbs, tbslen, (unsigned char*) &digest);
            break;
          case 4:
          case 5:
          default:
            classical_md = EVP_sha512();
            digest_len = SHA512_DIGEST_LENGTH;
            SHA512(tbs, tbslen, (unsigned char*) &digest);
            break;
          }
          if ((EVP_PKEY_CTX_set_signature_md(classical_ctx_sign, classical_md) <= 0) ||
              (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32, &actual_classical_sig_len, digest, digest_len) <= 0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            goto endsign;
          }
      /* activate in case we want to use pre-performed hashes:
       * }
       * else { // hashing done before; just sign:
       *     if (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32, &actual_classical_sig_len, tbs, tbslen) <= 0) {
       *       ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_SIGNING_FAILED);
       *       goto endsign;
       *     }
       *  }
       */
      if (actual_classical_sig_len > lwocryptxkey->evp_info->length_signature) {
        /* sig is bigger than expected */
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_BUFFER_LENGTH_WRONG);
        goto endsign;
      }
      ENCODE_UINT32(sig, actual_classical_sig_len);
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
    }

    if (LWOCRYPT_SIG_sign(lwocrypt_key, sig + index, &lwocrypt_sig_len, tbs, tbslen, lwocryptxkey->comp_privkey[lwocryptxkey->numkeys-1]) != LWOCRYPT_SUCCESS) {
      ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_SIGNING_FAILED);
      goto endsign;
    }
    *siglen = classical_sig_len + lwocrypt_sig_len;
    LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: signing completes with size %ld\n", *siglen);
    rv = 1; /* success */

 endsign:
    if (classical_ctx_sign) {
      EVP_PKEY_CTX_free(classical_ctx_sign);
    }
    return rv;
}

static int lwocrypt_sig_verify(void *vplwocrypt_sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    LWOCRYPTX_KEY* lwocryptxkey = plwocrypt_sigctx->sig;
    LWOCRYPT_SIG*  lwocrypt_key = plwocrypt_sigctx->sig->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig;
    EVP_PKEY* evpkey = lwocryptxkey->classical_pkey; // if this value is not NULL, we're running hybrid
    EVP_PKEY_CTX *classical_ctx_sign = NULL;
    EVP_PKEY_CTX *ctx_verify = NULL;
    int is_hybrid = evpkey!=NULL;
    size_t classical_sig_len = 0;
    size_t index = 0;
    int rv = 0;

    LWOCRYPT_SIG_PRINTF3("LWOCRYPT SIG provider: verify called with siglen %ld bytes and tbslen %ld\n", siglen, tbslen);

    if (!lwocryptxkey || !lwocrypt_key || !lwocryptxkey->pubkey || sig == NULL || (tbs == NULL && tbslen > 0)) {
      ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_WRONG_PARAMETERS);
      goto endverify;
    }

    if (is_hybrid) {
      const EVP_MD *classical_md;
      size_t actual_classical_sig_len = 0;
      int digest_len;
      unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

      if ((ctx_verify = EVP_PKEY_CTX_new(lwocryptxkey->classical_pkey, NULL)) == NULL ||
          EVP_PKEY_verify_init(ctx_verify) <= 0) {
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_VERIFY_ERROR);
        goto endverify;
      }
      if (lwocryptxkey->evp_info->keytype == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING) <= 0) {
          ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_WRONG_PARAMETERS);
          goto endverify;
        }
      }
      DECODE_UINT32(actual_classical_sig_len, sig);

      /* same as with sign: activate if pre-existing hashing to be used:
       *  if (plwocrypt_sigctx->mdctx == NULL) { // hashing not yet done
       */
      switch (lwocrypt_key->claimed_nist_level) {
      case 1:
        classical_md = EVP_sha256();
        digest_len = SHA256_DIGEST_LENGTH;
        SHA256(tbs, tbslen, (unsigned char*) &digest);
        break;
      case 2:
      case 3:
        classical_md = EVP_sha384();
        digest_len = SHA384_DIGEST_LENGTH;
        SHA384(tbs, tbslen, (unsigned char*) &digest);
        break;
      case 4:
      case 5:
      default:
        classical_md = EVP_sha512();
        digest_len = SHA512_DIGEST_LENGTH;
        SHA512(tbs, tbslen, (unsigned char*) &digest);
        break;
      }
      if ((EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <= 0) ||
          (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32, actual_classical_sig_len, digest, digest_len) <= 0)) {
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_VERIFY_ERROR);
        goto endverify;
      }
      else {
	LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG: classic verification OK\n");
      }
     /* activate for using pre-existing digest:
      * }
      *  else { // hashing already done:
      *     if (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32, actual_classical_sig_len, tbs, tbslen) <= 0) {
      *       ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_VERIFY_ERROR);
      *       goto endverify;
      *     }
      *  }
      */
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
    }

    if (!lwocryptxkey->comp_pubkey[lwocryptxkey->numkeys-1]) {
      ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_WRONG_PARAMETERS);
      goto endverify;
    }
    if (LWOCRYPT_SIG_verify(lwocrypt_key, tbs, tbslen, sig + index, siglen - classical_sig_len, lwocryptxkey->comp_pubkey[lwocryptxkey->numkeys-1]) != LWOCRYPT_SUCCESS) {
      ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_VERIFY_ERROR);
      goto endverify;
    }
    rv = 1;

 endverify:
    if (ctx_verify) {
      EVP_PKEY_CTX_free(ctx_verify);
    }
    LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: verify rv = %d\n", rv);
    return rv;
}

static int lwocrypt_sig_digest_signverify_init(void *vplwocrypt_sigctx, const char *mdname,
                                      void *vlwocryptsig, int operation)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: digest_signverify_init called for mdname %s\n", mdname);

    plwocrypt_sigctx->flag_allow_md = 1; /* permitted until first use */
    if (!lwocrypt_sig_signverify_init(vplwocrypt_sigctx, vlwocryptsig, operation))
        return 0;

    if (!lwocrypt_sig_setup_md(plwocrypt_sigctx, mdname, NULL))
        return 0;

    if (mdname != NULL) {
       plwocrypt_sigctx->mdctx = EVP_MD_CTX_new();
       if (plwocrypt_sigctx->mdctx == NULL)
           goto error;

       if (!EVP_DigestInit_ex(plwocrypt_sigctx->mdctx, plwocrypt_sigctx->md, NULL))
           goto error;
    }

    return 1;

 error:
    EVP_MD_CTX_free(plwocrypt_sigctx->mdctx);
    EVP_MD_free(plwocrypt_sigctx->md);
    plwocrypt_sigctx->mdctx = NULL;
    plwocrypt_sigctx->md = NULL;
    LWOCRYPT_SIG_PRINTF("   LWOCRYPT SIG provider: digest_signverify FAILED\n");
    return 0;
}

static int lwocrypt_sig_digest_sign_init(void *vplwocrypt_sigctx, const char *mdname,
                                      void *vlwocryptsig, const OSSL_PARAM params[])
{
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: digest_sign_init called\n");
    return lwocrypt_sig_digest_signverify_init(vplwocrypt_sigctx, mdname, vlwocryptsig, EVP_PKEY_OP_SIGN);
}

static int lwocrypt_sig_digest_verify_init(void *vplwocrypt_sigctx, const char *mdname, void *vlwocryptsig, const OSSL_PARAM params[])
{
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: sig_digest_verify called\n");
    return lwocrypt_sig_digest_signverify_init(vplwocrypt_sigctx, mdname, vlwocryptsig, EVP_PKEY_OP_VERIFY);
}

int lwocrypt_sig_digest_signverify_update(void *vplwocrypt_sigctx, const unsigned char *data,
                                 size_t datalen)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: digest_signverify_update called\n");

    if (plwocrypt_sigctx == NULL)
        return 0;
    // disallow MD changes after update has been called at least once
    plwocrypt_sigctx->flag_allow_md = 0;

    if (plwocrypt_sigctx->mdctx) 
    	return EVP_DigestUpdate(plwocrypt_sigctx->mdctx, data, datalen);
    else {
    // unconditionally collect data for passing in full to LWOCRYPT API
      if (plwocrypt_sigctx->mddata) {
	unsigned char* newdata = OPENSSL_realloc(plwocrypt_sigctx->mddata, plwocrypt_sigctx->mdsize+datalen);
	if (newdata == NULL) return 0;
	memcpy(newdata+plwocrypt_sigctx->mdsize, data, datalen);
	plwocrypt_sigctx->mddata = newdata;
	plwocrypt_sigctx->mdsize += datalen;
      }
      else { // simple alloc and copy
	plwocrypt_sigctx->mddata = OPENSSL_malloc(datalen);
	if (plwocrypt_sigctx->mddata == NULL) return 0;
	plwocrypt_sigctx->mdsize=datalen;
	memcpy(plwocrypt_sigctx->mddata, data, plwocrypt_sigctx->mdsize);
      }
      LWOCRYPT_SIG_PRINTF2("LWOCRYPT SIG provider: digest_signverify_update collected %ld bytes...\n", plwocrypt_sigctx->mdsize);
    }
    return 1;
}

int lwocrypt_sig_digest_sign_final(void *vplwocrypt_sigctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: digest_sign_final called\n");
    if (plwocrypt_sigctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to lwocrypt_sig_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just here.
         */
	if (plwocrypt_sigctx->mdctx != NULL)
        	if (!EVP_DigestFinal_ex(plwocrypt_sigctx->mdctx, digest, &dlen))
            		return 0;
    }

    plwocrypt_sigctx->flag_allow_md = 1;

    if (plwocrypt_sigctx->mdctx != NULL) 
	return lwocrypt_sig_sign(vplwocrypt_sigctx, sig, siglen, sigsize, digest, (size_t)dlen);
    else
	return lwocrypt_sig_sign(vplwocrypt_sigctx, sig, siglen, sigsize, plwocrypt_sigctx->mddata, plwocrypt_sigctx->mdsize);
	
}


int lwocrypt_sig_digest_verify_final(void *vplwocrypt_sigctx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: digest_verify_final called\n");
    if (plwocrypt_sigctx == NULL)
        return 0;

    // TBC for hybrids:
    if (plwocrypt_sigctx->mdctx) {
	if (!EVP_DigestFinal_ex(plwocrypt_sigctx->mdctx, digest, &dlen))
        	return 0;

    	plwocrypt_sigctx->flag_allow_md = 1;

    	return lwocrypt_sig_verify(vplwocrypt_sigctx, sig, siglen, digest, (size_t)dlen);
    }
    else 
    	return lwocrypt_sig_verify(vplwocrypt_sigctx, sig, siglen, plwocrypt_sigctx->mddata, plwocrypt_sigctx->mdsize);
}

static void lwocrypt_sig_freectx(void *vplwocrypt_sigctx)
{
    PROV_LWOCRYPTSIG_CTX *ctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: freectx called\n");
    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    lwocryptx_key_free(ctx->sig);
    OPENSSL_free(ctx->mddata);
    ctx->mddata = NULL;
    ctx->mdsize = 0;
    OPENSSL_free(ctx->aid);
    ctx->aid = NULL;
    ctx->aid_len = 0;
    OPENSSL_free(ctx);
}

static void *lwocrypt_sig_dupctx(void *vplwocrypt_sigctx)
{
    PROV_LWOCRYPTSIG_CTX *srcctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    PROV_LWOCRYPTSIG_CTX *dstctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: dupctx called\n");

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->sig = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->sig != NULL && !lwocryptx_key_up_ref(srcctx->sig))
        goto err;
    dstctx->sig = srcctx->sig;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->mddata) {
	dstctx->mddata=OPENSSL_memdup(srcctx->mddata, srcctx->mdsize);
	if (dstctx->mddata == NULL)
            goto err;
	dstctx->mdsize = srcctx->mdsize;
    }

    if (srcctx->aid) {
      dstctx->aid = OPENSSL_memdup(srcctx->aid, srcctx->aid_len);
      if (dstctx->aid == NULL)
        goto err;
      dstctx->aid_len = srcctx->aid_len;
    }

    if (srcctx->propq) {
      dstctx->propq = OPENSSL_strdup(srcctx->propq);
      if (dstctx->propq == NULL)
        goto err;
    }

    return dstctx;
 err:
    lwocrypt_sig_freectx(dstctx);
    return NULL;
}

static int lwocrypt_sig_get_ctx_params(void *vplwocrypt_sigctx, OSSL_PARAM *params)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    OSSL_PARAM *p;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: get_ctx_params called\n");
    if (plwocrypt_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);

    if (plwocrypt_sigctx->aid == NULL) {
        plwocrypt_sigctx->aid_len = get_aid(&(plwocrypt_sigctx->aid), plwocrypt_sigctx->sig->tls_name);
    }

    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, plwocrypt_sigctx->aid, plwocrypt_sigctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, plwocrypt_sigctx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *lwocrypt_sig_gettable_ctx_params(ossl_unused void *vplwocrypt_sigctx, ossl_unused void *vctx)
{
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: gettable_ctx_params called\n");
    return known_gettable_ctx_params;
}
static int lwocrypt_sig_set_ctx_params(void *vplwocrypt_sigctx, const OSSL_PARAM params[])
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;
    const OSSL_PARAM *p;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: set_ctx_params called\n");
    if (plwocrypt_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !plwocrypt_sigctx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!lwocrypt_sig_setup_md(plwocrypt_sigctx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *lwocrypt_sig_settable_ctx_params(ossl_unused void *vpsm2ctx,
                                                     ossl_unused void *provctx)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     * NOTE: Ideally we would check plwocrypt_sigctx->flag_allow_md, but this is
     * problematic because there is no nice way of passing the
     * PROV_LWOCRYPTSIG_CTX down to this function...
     * Because we have API's that dont know about their parent..
     * e.g: EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig).
     * We could pass NULL for that case (but then how useful is the check?).
     */
    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: settable_ctx_params called\n");
    return known_settable_ctx_params;
}

static int lwocrypt_sig_get_ctx_md_params(void *vplwocrypt_sigctx, OSSL_PARAM *params)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: get_ctx_md_params called\n");
    if (plwocrypt_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(plwocrypt_sigctx->mdctx, params);
}

static const OSSL_PARAM *lwocrypt_sig_gettable_ctx_md_params(void *vplwocrypt_sigctx)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: gettable_ctx_md_params called\n");
    if (plwocrypt_sigctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(plwocrypt_sigctx->md);
}

static int lwocrypt_sig_set_ctx_md_params(void *vplwocrypt_sigctx, const OSSL_PARAM params[])
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: set_ctx_md_params called\n");
    if (plwocrypt_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(plwocrypt_sigctx->mdctx, params);
}

static const OSSL_PARAM *lwocrypt_sig_settable_ctx_md_params(void *vplwocrypt_sigctx)
{
    PROV_LWOCRYPTSIG_CTX *plwocrypt_sigctx = (PROV_LWOCRYPTSIG_CTX *)vplwocrypt_sigctx;

    if (plwocrypt_sigctx->md == NULL)
        return 0;

    LWOCRYPT_SIG_PRINTF("LWOCRYPT SIG provider: settable_ctx_md_params called\n");
    return EVP_MD_settable_ctx_params(plwocrypt_sigctx->md);
}

const OSSL_DISPATCH lwocrypt_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))lwocrypt_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))lwocrypt_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))lwocrypt_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))lwocrypt_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))lwocrypt_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))lwocrypt_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))lwocrypt_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))lwocrypt_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))lwocrypt_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))lwocrypt_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))lwocrypt_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))lwocrypt_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))lwocrypt_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))lwocrypt_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))lwocrypt_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))lwocrypt_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))lwocrypt_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))lwocrypt_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lwocrypt_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))lwocrypt_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lwocrypt_sig_settable_ctx_md_params },
    { 0, NULL }
};
