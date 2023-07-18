// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * LWOCRYPT OpenSSL 3 key handler.
 * 
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here 
 * to have code within provider.
 *
 */

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <assert.h>
#include "lwocrypt_prov.h"

#ifdef NDEBUG
#define LWOCRYPT_KEY_PRINTF(a)
#define LWOCRYPT_KEY_PRINTF2(a, b)
#define LWOCRYPT_KEY_PRINTF3(a, b, c)
#else
#define LWOCRYPT_KEY_PRINTF(a) if (getenv("LWOCRYPTKEY")) printf(a)
#define LWOCRYPT_KEY_PRINTF2(a, b) if (getenv("LWOCRYPTKEY")) printf(a, b)
#define LWOCRYPT_KEY_PRINTF3(a, b, c) if (getenv("LWOCRYPTKEY")) printf(a, b, c)
#endif // NDEBUG

typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} lwocryptx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char* tlsname;
    char* lwocryptname;
    int keytype;
    int secbits;
} lwocrypt_nid_name_t;

static int lwocryptx_key_recreate_classickey(LWOCRYPTX_KEY *key, lwocryptx_key_op_t op);

///// LWOCRYPT_TEMPLATE_FRAGMENT_LWOCRYPTNAMES_START
#define NID_TABLE_LEN 23

static lwocrypt_nid_name_t nid_names[NID_TABLE_LEN] = {
       { 0, "dilithium2", LWOCRYPT_SIG_alg_dilithium_2, KEY_TYPE_SIG, 128 },
       { 0, "p256_dilithium2", LWOCRYPT_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_dilithium2", LWOCRYPT_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128 },
       { 0, "dilithium3", LWOCRYPT_SIG_alg_dilithium_3, KEY_TYPE_SIG, 192 },
       { 0, "p384_dilithium3", LWOCRYPT_SIG_alg_dilithium_3, KEY_TYPE_HYB_SIG, 192 },
       { 0, "dilithium5", LWOCRYPT_SIG_alg_dilithium_5, KEY_TYPE_SIG, 256 },
       { 0, "p521_dilithium5", LWOCRYPT_SIG_alg_dilithium_5, KEY_TYPE_HYB_SIG, 256 },
       { 0, "falcon512", LWOCRYPT_SIG_alg_falcon_512, KEY_TYPE_SIG, 128 },
       { 0, "p256_falcon512", LWOCRYPT_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_falcon512", LWOCRYPT_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128 },
       { 0, "falcon1024", LWOCRYPT_SIG_alg_falcon_1024, KEY_TYPE_SIG, 256 },
       { 0, "p521_falcon1024", LWOCRYPT_SIG_alg_falcon_1024, KEY_TYPE_HYB_SIG, 256 },
       { 0, "sphincssha2128fsimple", LWOCRYPT_SIG_alg_sphincs_sha2_128f_simple, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincssha2128fsimple", LWOCRYPT_SIG_alg_sphincs_sha2_128f_simple, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincssha2128fsimple", LWOCRYPT_SIG_alg_sphincs_sha2_128f_simple, KEY_TYPE_HYB_SIG, 128 },
       { 0, "sphincssha2128ssimple", LWOCRYPT_SIG_alg_sphincs_sha2_128s_simple, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincssha2128ssimple", LWOCRYPT_SIG_alg_sphincs_sha2_128s_simple, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincssha2128ssimple", LWOCRYPT_SIG_alg_sphincs_sha2_128s_simple, KEY_TYPE_HYB_SIG, 128 },
       { 0, "sphincssha2192fsimple", LWOCRYPT_SIG_alg_sphincs_sha2_192f_simple, KEY_TYPE_SIG, 192 },
       { 0, "p384_sphincssha2192fsimple", LWOCRYPT_SIG_alg_sphincs_sha2_192f_simple, KEY_TYPE_HYB_SIG, 192 },
       { 0, "sphincsshake128fsimple", LWOCRYPT_SIG_alg_sphincs_shake_128f_simple, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincsshake128fsimple", LWOCRYPT_SIG_alg_sphincs_shake_128f_simple, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincsshake128fsimple", LWOCRYPT_SIG_alg_sphincs_shake_128f_simple, KEY_TYPE_HYB_SIG, 128 },
///// LWOCRYPT_TEMPLATE_FRAGMENT_LWOCRYPTNAMES_END
};

int lwocrypt_set_nid(char* tlsname, int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (!strcmp(nid_names[i].tlsname, tlsname)) {
          nid_names[i].nid = nid;
          return 1;
      }
   }
   return 0;
}

static int get_secbits(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].secbits;
   }
   return 0; 
}

static int get_keytype(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].keytype;
   }
   return 0; 
}

static char* get_lwocryptname(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].lwocryptname;
   }
   return 0; 
}

static int get_lwocryptalg_idx(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return i;
   }
   return -1; 
}

/* Prepare composite data structures. RetVal 0 is error. */
static int lwocryptx_key_set_composites(LWOCRYPTX_KEY *key) {
	int ret = 1;

	LWOCRYPT_KEY_PRINTF2("Setting composites with evp_info %p\n", key->evp_info);

	if (key->numkeys == 1) {
		key->comp_privkey[0] = key->privkey;
		key->comp_pubkey[0] = key->pubkey;
	}
	else { // TBD: extend for more than 1 classic key:
		int classic_pubkey_len, classic_privkey_len;

		if (key->privkey) {
			key->comp_privkey[0] = (char*)key->privkey + SIZE_OF_UINT32;
			DECODE_UINT32(classic_privkey_len, key->privkey);
			key->comp_privkey[1] = (char*)key->privkey + classic_privkey_len + SIZE_OF_UINT32;
		}
		else {
			key->comp_privkey[0] = NULL;
			key->comp_privkey[1] = NULL;
		}
		if (key->pubkey) {
			key->comp_pubkey[0] = (char*)key->pubkey + SIZE_OF_UINT32;
			DECODE_UINT32(classic_pubkey_len, key->pubkey);
			key->comp_pubkey[1] = (char*)key->pubkey + classic_pubkey_len + SIZE_OF_UINT32;
		}
		else {

			key->comp_pubkey[0] = NULL;
			key->comp_pubkey[1] = NULL;
		}
	}
	return ret;
}

PROV_LWOCRYPT_CTX *lwocryptx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm) {
    PROV_LWOCRYPT_CTX * ret = OPENSSL_zalloc(sizeof(PROV_LWOCRYPT_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->handle = handle;
       ret->corebiometh = bm;
    }
    return ret;
}

void lwocryptx_freeprovctx(PROV_LWOCRYPT_CTX *ctx) {
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}


void lwocryptx_key_set0_libctx(LWOCRYPTX_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

/* convenience function creating LWOCRYPTX keys from nids (only for sigs) */
static LWOCRYPTX_KEY *lwocryptx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq, int nid) {
	LWOCRYPT_KEY_PRINTF2("Generating LWOCRYPTX key for nid %d\n", nid);

	char* tls_algname = (char *)OBJ_nid2sn(nid);
	LWOCRYPT_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

	if (!tls_algname) {
		ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_WRONG_PARAMETERS);
		return NULL;
	}

	return lwocryptx_key_new(libctx, get_lwocryptname(nid), tls_algname, get_keytype(nid), propq, get_secbits(nid), get_lwocryptalg_idx(nid));
}

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY* setECParams(EVP_PKEY *eck, int nid) {
    const unsigned char p256params[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const unsigned char p384params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    const unsigned char p521params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

    const unsigned char* params;
    switch(nid) {
        case NID_X9_62_prime256v1:
            params = p256params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
        case NID_secp384r1:
            params = p384params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
        case NID_secp521r1:
            params = p521params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
        default:
            return NULL;
    }
}

/* Re-create LWOCRYPTX_KEY from encoding(s): Same end-state as after ken-gen */
static LWOCRYPTX_KEY *lwocryptx_key_op(const X509_ALGOR *palg,
                      const unsigned char *p, int plen,
                      lwocryptx_key_op_t op,
                      OSSL_LIB_CTX *libctx, const char *propq)
{
    LWOCRYPTX_KEY *key = NULL;
    void **privkey, **pubkey;
    int nid = NID_undef;
    int ret = 0;

    LWOCRYPT_KEY_PRINTF2("LWOCRYPTX KEY: key_op called with data of len %d\n", plen);
    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF || !palg || !palg->algorithm) {
            ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
            return 0;
        }
        nid = OBJ_obj2nid(palg->algorithm);
    }

    if (p == NULL || nid == EVP_PKEY_NONE || nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
        return 0;
    }

    key = lwocryptx_key_new_from_nid(libctx, propq, nid);
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (op == KEY_OP_PUBLIC) {
#ifdef USE_ENCODING_LIB
        if (key->lwocryptx_encoding_ctx.encoding_ctx && key->lwocryptx_encoding_ctx.encoding_impl) {
            key->pubkeylen = key->lwocryptx_encoding_ctx.encoding_ctx->raw_crypto_publickeybytes;
            if (key->lwocryptx_encoding_ctx.encoding_impl->crypto_publickeybytes != plen) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
            }
            if (lwocryptx_key_allocate_keymaterial(key, 0)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (qsc_decode(key->lwocryptx_encoding_ctx.encoding_ctx, key->lwocryptx_encoding_ctx.encoding_impl, p, (unsigned char **) &key->pubkey, 0, 0, 1) != QSC_ENC_OK) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
            }
        } else {
#endif
            if (key->pubkeylen != plen) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
            }
            if (lwocryptx_key_allocate_keymaterial(key, 0)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            memcpy(key->pubkey, p, plen);
#ifdef USE_ENCODING_LIB
        }
#endif
    } else {
    	int classical_privatekey_len = 0;
    	// for plain LWOCRYPT keys, we expect LWOCRYPT priv||LWOCRYPT pub key
    	size_t actualprivkeylen = key->privkeylen;
    	// for hybrid keys, we expect classic priv key||LWOCRYPT priv key||LWOCRYPT pub key
    	// classic pub key must/can be re-created from classic private key
    	if (key->numkeys == 2) {
                DECODE_UINT32(classical_privatekey_len, p); // actual classic key len
    	    // adjust expected size
    	    if (classical_privatekey_len > key->evp_info->length_private_key) {
                    ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                    goto err;
    	    }
    	    actualprivkeylen -= (key->evp_info->length_private_key - classical_privatekey_len);
    	}
#ifdef USE_ENCODING_LIB
        if (key->lwocryptx_encoding_ctx.encoding_ctx && key->lwocryptx_encoding_ctx.encoding_impl) {
             const qsc_encoding_t* encoding_ctx = key->lwocryptx_encoding_ctx.encoding_ctx;
#ifdef NOPUBKEY_IN_PRIVKEY
            // if the raw private key includes the public key, the optional part is needed, otherwise not.
            int withoptional = (encoding_ctx->raw_private_key_encodes_public_key ? 1 : 0);
#else
            int withoptional = 1;
#endif
            int pubkey_available = withoptional;
            if (lwocryptx_key_allocate_keymaterial(key, 1)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (pubkey_available) {
                if (lwocryptx_key_allocate_keymaterial(key, 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err;
                }
            }

            if (qsc_decode(encoding_ctx, key->lwocryptx_encoding_ctx.encoding_impl, 
                        0, (pubkey_available ? (unsigned char**)&key->pubkey : 0), p, 
                        (unsigned char**)&key->privkey, withoptional) != QSC_ENC_OK) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
            }

        } else {
#endif
#ifdef NOPUBKEY_IN_PRIVKEY
        if (actualprivkeylen != plen) {
                LWOCRYPT_KEY_PRINTF3("LWOCRYPTX KEY: private key with unexpected length %d vs %d\n", plen, (int)(actualprivkeylen));
#else
        if (actualprivkeylen + lwocryptx_key_get_lwocrypt_public_key_len(key) != plen) {
                LWOCRYPT_KEY_PRINTF3("LWOCRYPTX KEY: private key with unexpected length %d vs %d\n", plen, (int)(actualprivkeylen + lwocryptx_key_get_lwocrypt_public_key_len(key)));
#endif
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
        }
        if (lwocryptx_key_allocate_keymaterial(key, 1)
#ifndef NOPUBKEY_IN_PRIVKEY
    		|| lwocryptx_key_allocate_keymaterial(key, 0)
#endif
    			) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
    	// first populate private key data
            memcpy(key->privkey, p, actualprivkeylen);
#ifndef NOPUBKEY_IN_PRIVKEY
    	// only enough data to fill public LWOCRYPT key component
    	if (lwocryptx_key_get_lwocrypt_public_key_len(key) != plen - actualprivkeylen) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto err;
        }
    	// populate LWOCRYPT public key structure
    	if (key->numkeys == 2) {
                unsigned char *pubkey = (unsigned char *)key->pubkey;
                ENCODE_UINT32(pubkey,key->evp_info->length_public_key);
                memcpy(pubkey+SIZE_OF_UINT32+key->evp_info->length_public_key, p+actualprivkeylen, plen-actualprivkeylen);
    	}
    	else
                memcpy(key->pubkey, p+key->privkeylen, plen-key->privkeylen);
#endif
        }
#ifdef USE_ENCODING_LIB
    }
#endif
    if (!lwocryptx_key_set_composites(key) || !lwocryptx_key_recreate_classickey(key, op))
	goto err;

    return key;

 err:
    lwocryptx_key_free(key);
    return NULL;
}

/* Recreate EVP data structure after import. RetVal 0 is error. */
static int lwocryptx_key_recreate_classickey(LWOCRYPTX_KEY *key, lwocryptx_key_op_t op) {
    if (key->numkeys == 2) { // hybrid key
        int classical_pubkey_len, classical_privkey_len;
        if (!key->evp_info) {
            ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_EVPINFO_MISSING);
            goto rec_err;
        }
        if (op == KEY_OP_PUBLIC) {
            DECODE_UINT32(classical_pubkey_len, key->pubkey);
            if (key->evp_info->raw_key_support) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto rec_err;
            }
            else {
                const unsigned char* enc_pubkey = key->comp_pubkey[0];
                EVP_PKEY* npk = EVP_PKEY_new();
                if (key->evp_info->keytype != EVP_PKEY_RSA) {
                    npk = setECParams(npk, key->evp_info->nid);
                }
                key->classical_pkey = d2i_PublicKey(key->evp_info->keytype, &npk, &enc_pubkey, classical_pubkey_len);
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                    EVP_PKEY_free(npk);
                    goto rec_err;
                }
            }
        }
        if (op == KEY_OP_PRIVATE) {
            DECODE_UINT32(classical_privkey_len, key->privkey);
            if (key->evp_info->raw_key_support) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                goto rec_err;
            }
            else {
                const unsigned char* enc_privkey = key->comp_privkey[0];
                unsigned char* enc_pubkey = key->comp_pubkey[0];
                key->classical_pkey = d2i_PrivateKey(key->evp_info->keytype, NULL, &enc_privkey, classical_privkey_len);
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
#ifndef NOPUBKEY_IN_PRIVKEY
		// re-create classic public key part from private key:
		int pubkeylen = i2d_PublicKey(key->classical_pkey, &enc_pubkey);
		if (pubkeylen != key->evp_info->length_public_key) {
                    ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
#endif
            }
        }
    }
    return 1;
    rec_err:
	return 0;
}

LWOCRYPTX_KEY *lwocryptx_key_from_x509pubkey(const X509_PUBKEY *xpk,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    LWOCRYPTX_KEY* lwocryptx = NULL;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    lwocryptx = lwocryptx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    return lwocryptx;
}

LWOCRYPTX_KEY *lwocryptx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    LWOCRYPTX_KEY *lwocryptx = NULL;
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    lwocryptx = lwocryptx_key_op(palg, p, plen, KEY_OP_PRIVATE,
                       libctx, propq);
    ASN1_OCTET_STRING_free(oct);
    return lwocryptx;
}

/* Key codes */

static const LWOCRYPTX_EVP_INFO nids_sig[] = {
        { EVP_PKEY_EC,  NID_X9_62_prime256v1, 0, 65 , 121,  32,  72}, // 128 bit
        { EVP_PKEY_EC,  NID_secp384r1       , 0, 97 , 167,  48, 104}, // 192 bit
        { EVP_PKEY_EC,  NID_secp521r1       , 0, 133, 223,  66, 141}, // 256 bit
        { EVP_PKEY_RSA, NID_rsaEncryption   , 0, 398, 1770, 0,  384}, // 128 bit
};

// These two array need to stay synced:
static const char* LWOCRYPTX_ECP_NAMES[] = { "p256", "p384", "p521", 0 };
static const LWOCRYPTX_EVP_INFO nids_ecp[] = {
        { EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65 , 121, 32, 0}, // 128 bit
        { EVP_PKEY_EC, NID_secp384r1       , 0, 97 , 167, 48, 0}, // 192 bit
        { EVP_PKEY_EC, NID_secp521r1       , 0, 133, 223, 66, 0}  // 256 bit
};

// These two array need to stay synced:
static const char* LWOCRYPTX_ECX_NAMES[] = { "x25519", "x448", 0 };
static const LWOCRYPTX_EVP_INFO nids_ecx[] = {
        { EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
        { EVP_PKEY_X448,   0, 1, 56, 56, 56, 0}, // 192 bit
        { 0,               0, 0,  0,  0,  0, 0}  // 256 bit
};

static int lwocryptx_hybsig_init(int bit_security, LWOCRYPTX_EVP_CTX *evp_ctx, char* algname)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    if (!strncmp(algname, "rsa3072_", 8)) idx += 3;
    else if (algname[0]!='p') {
        LWOCRYPT_KEY_PRINTF2("LWOCRYPT KEY: Incorrect hybrid name: %s\n", algname);
        ret = 0;
        goto err;
    }

    ON_ERR_GOTO(idx < 0 || idx > 3, err);

    evp_ctx->evp_info = &nids_sig[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err);

    if (idx < 3) { // EC
	ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
	ON_ERR_GOTO(ret <= 0, err);

        ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx, evp_ctx->evp_info->nid);
	ON_ERR_GOTO(ret <= 0, err);

	ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
	ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err);
    }
    // RSA bit length set only during keygen

    err:
    return ret;
}

static const int lwocrypthybkem_init_ecp(char* tls_name, LWOCRYPTX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = 0;
    while(idx < sizeof(LWOCRYPTX_ECP_NAMES)) {
        if (!strncmp(tls_name, LWOCRYPTX_ECP_NAMES[idx], 4))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->evp_info = &nids_ecp[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err);

    ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx, evp_ctx->evp_info->nid);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err);

    err:
    return ret;
}

static const int lwocrypthybkem_init_ecx(char* tls_name, LWOCRYPTX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = 0;

    while(idx < sizeof(LWOCRYPTX_ECX_NAMES)) {
        if (!strncmp(tls_name, LWOCRYPTX_ECX_NAMES[idx], 4))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->evp_info = &nids_ecx[idx];

    evp_ctx->keyParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err);

    ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err);

    err:
    return ret;
}

static const int (*init_kex_fun[])(char *, LWOCRYPTX_EVP_CTX *) = {
        lwocrypthybkem_init_ecp,
        lwocrypthybkem_init_ecx
};
#ifdef USE_ENCODING_LIB
extern const char* lwocrypt_alg_encoding_list[];
#endif
extern const char* lwocrypt_oid_alg_list[];

LWOCRYPTX_KEY *lwocryptx_key_new(OSSL_LIB_CTX *libctx, char* lwocrypt_name, char* tls_name, int primitive, const char *propq, int bit_security, int alg_idx)
{
    LWOCRYPTX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));
    LWOCRYPTX_EVP_CTX *evp_ctx = NULL;
    int ret2 = 0;

    if (ret == NULL) goto err;

#ifdef LWOCRYPT_PROVIDER_NOATOMIC
     ret->lock = CRYPTO_THREAD_lock_new();
     if (ret->lock == NULL) {
         OPENSSL_free(ret);
         goto err;
     }
#endif

    if (lwocrypt_name == NULL) {
        LWOCRYPT_KEY_PRINTF("LWOCRYPTX_KEY: Fatal error: No LWOCRYPT key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        LWOCRYPT_KEY_PRINTF("LWOCRYPTX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch(primitive) {
    case KEY_TYPE_SIG:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig = LWOCRYPT_SIG_new(lwocrypt_name);
        if (!ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig) {
            fprintf(stderr, "Could not create LWOCRYPT signature algorithm %s. Enabled in liblwocrypt?\n", lwocrypt_name);
            goto err;
        }

#ifdef USE_ENCODING_LIB
        if (alg_idx >= 0 && lwocrypt_alg_encoding_list[2*alg_idx] != NULL && lwocrypt_alg_encoding_list[2*alg_idx+1] != NULL) {
            if (qsc_encoding_by_name_oid(&ret->lwocryptx_encoding_ctx.encoding_ctx, &ret->lwocryptx_encoding_ctx.encoding_impl, lwocrypt_alg_encoding_list[2*alg_idx+1], lwocrypt_alg_encoding_list[2*alg_idx]) != QSC_ENC_OK) {
                fprintf(stderr, "Could not create LWOCRYPT signature encoding algorithm %s (%s, %s).\n", lwocrypt_alg_encoding_list[2*alg_idx+1], lwocrypt_name, lwocrypt_alg_encoding_list[2*alg_idx]);
                ret->lwocryptx_encoding_ctx.encoding_ctx = NULL;
                ret->lwocryptx_encoding_ctx.encoding_impl = NULL;
                goto err;
            }
        }
#endif
        ret->privkeylen = ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen = ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
	break;
    case KEY_TYPE_KEM:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem = LWOCRYPT_KEM_new(lwocrypt_name);
        if (!ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem) {
            fprintf(stderr, "Could not create LWOCRYPT KEM algorithm %s. Enabled in liblwocrypt?\n", lwocrypt_name);
            goto err;
        }
        ret->privkeylen = ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen = ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
	break;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem = LWOCRYPT_KEM_new(lwocrypt_name);
        if (!ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem) {
            fprintf(stderr, "Could not create LWOCRYPT KEM algorithm %s. Enabled in liblwocrypt?\n", lwocrypt_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(LWOCRYPTX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])
                (tls_name, evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->keyParam || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->privkeylen = (ret->numkeys-1)*SIZE_OF_UINT32 + ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_secret_key + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen = (ret->numkeys-1)*SIZE_OF_UINT32 + ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_public_key + evp_ctx->evp_info->length_public_key;
        ret->lwocryptx_provider_ctx.lwocryptx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
	break;
    case KEY_TYPE_HYB_SIG:
        ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig = LWOCRYPT_SIG_new(lwocrypt_name);
        if (!ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig) {
            fprintf(stderr, "Could not create LWOCRYPT signature algorithm %s. Enabled in liblwocrypt?\n", lwocrypt_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(LWOCRYPTX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

	ret2 = lwocryptx_hybsig_init(bit_security, evp_ctx, tls_name);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->privkeylen = (ret->numkeys-1) * SIZE_OF_UINT32 + ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_secret_key + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen = (ret->numkeys-1) * SIZE_OF_UINT32 + ret->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_public_key + evp_ctx->evp_info->length_public_key;
        ret->lwocryptx_provider_ctx.lwocryptx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
	ret->evp_info = evp_ctx->evp_info;
	break;
    default: 
        LWOCRYPT_KEY_PRINTF2("LWOCRYPTX_KEY: Unknown key type encountered: %d\n", primitive);
	goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        if (ret->propq == NULL)
            goto err;
    }

    LWOCRYPT_KEY_PRINTF2("LWOCRYPTX_KEY: new key created: %p\n", ret);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
}

void lwocryptx_key_free(LWOCRYPTX_KEY *key)
{
    int refcnt;

    if (key == NULL)
        return;

#ifndef LWOCRYPT_PROVIDER_NOATOMIC
    refcnt = atomic_fetch_sub_explicit(&key->references, 1,
                                       memory_order_relaxed) - 1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#else
    CRYPTO_atomic_add(&key->references, -1, &refcnt, key->lock);
#endif

    LWOCRYPT_KEY_PRINTF3("%p:%4d:LWOCRYPTX_KEY\n", (void*)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_free(key->tls_name);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_KEM)
        LWOCRYPT_KEM_free(key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        LWOCRYPT_KEM_free(key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem);
        EVP_PKEY_CTX_free(key->lwocryptx_provider_ctx.lwocryptx_evp_ctx->ctx);
        EVP_PKEY_free(key->lwocryptx_provider_ctx.lwocryptx_evp_ctx->keyParam);
        OPENSSL_free(key->lwocryptx_provider_ctx.lwocryptx_evp_ctx);
    } else
        LWOCRYPT_SIG_free(key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig);
    OPENSSL_free(key->classical_pkey);
#ifdef LWOCRYPT_PROVIDER_NOATOMIC
    CRYPTO_THREAD_lock_free(key->lock);
#endif
    OPENSSL_free(key);
}

int lwocryptx_key_up_ref(LWOCRYPTX_KEY *key)
{
    int refcnt;

#ifndef LWOCRYPT_PROVIDER_NOATOMIC
    refcnt = atomic_fetch_add_explicit(&key->references, 1,
                                       memory_order_relaxed) + 1;
#else
    CRYPTO_atomic_add(&key->references, 1, &refcnt, key->lock);
#endif

    LWOCRYPT_KEY_PRINTF3("%p:%4d:LWOCRYPTX_KEY\n", (void*)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int lwocryptx_key_allocate_keymaterial(LWOCRYPTX_KEY *key, int include_private)
{
    int ret = 0;

    if (!key->privkey && include_private) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err);
    }
    if (!key->pubkey && !include_private) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err);
    }
    err:
    return ret;
}

int lwocryptx_key_fromdata(LWOCRYPTX_KEY *key, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *p;

    LWOCRYPT_KEY_PRINTF("LWOCRYPTX Key from data called\n");
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, p->data_size);
        key->privkey = OPENSSL_secure_malloc(p->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, p->data, p->data_size);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            LWOCRYPT_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, p->data_size);
        key->pubkey = OPENSSL_secure_malloc(p->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, p->data, p->data_size);
    }
    if (!lwocryptx_key_set_composites(key) || !lwocryptx_key_recreate_classickey(key, key->privkey!=NULL?KEY_OP_PRIVATE:KEY_OP_PUBLIC))
        return 0;
    return 1;
}

// LWOCRYPT key always the last of the numkeys comp keys
static int lwocryptx_key_gen_lwocrypt(LWOCRYPTX_KEY *key, int gen_kem) {
	if (gen_kem)
		return LWOCRYPT_KEM_keypair(key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem, key->comp_pubkey[key->numkeys-1], key->comp_privkey[key->numkeys-1]);
	else
		return LWOCRYPT_SIG_keypair(key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig, key->comp_pubkey[key->numkeys-1], key->comp_privkey[key->numkeys-1]);
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of pubkey/privkey buffers;
 * returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY* lwocryptx_key_gen_evp_key(LWOCRYPTX_EVP_CTX *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    int ret = 0, ret2 = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;

    size_t pubkeylen = 0, privkeylen = 0;

    if (ctx->keyParam)
       kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
       kgctx = EVP_PKEY_CTX_new_id( ctx->evp_info->nid, NULL );
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    if (ctx->evp_info->keytype == EVP_PKEY_RSA) {
	ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 3072);
	ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    }
    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
        ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key || !pubkey_encoded, ret, -3, errhyb);
        memcpy(pubkey+SIZE_OF_UINT32, pubkey_encoded, pubkeylen);
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey+SIZE_OF_UINT32, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 || privkeylen != ctx->evp_info->length_private_key, ret, -4, errhyb);
    }
    else {
        unsigned char* pubkey_enc = pubkey+SIZE_OF_UINT32;
        const unsigned char* pubkey_enc2 = pubkey+SIZE_OF_UINT32;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc || pubkeylen > (int) ctx->evp_info->length_public_key, ret, -11, errhyb);
        unsigned char* privkey_enc = privkey+SIZE_OF_UINT32;
        const unsigned char* privkey_enc2 = privkey+SIZE_OF_UINT32;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc || privkeylen > (int) ctx->evp_info->length_private_key, ret, -12, errhyb);
        // selftest:
        EVP_PKEY* ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL, &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
    }
    ENCODE_UINT32(pubkey,pubkeylen);
    ENCODE_UINT32(privkey,privkeylen);
    LWOCRYPT_KEY_PRINTF3("LWOCRYPTKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n", privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

    errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* allocates LWOCRYPT and classical keys; retains EVP_PKEY on success for sig LWOCRYPTX_KEY */
int lwocryptx_key_gen(LWOCRYPTX_KEY *key)
{
    int ret = 0;
    EVP_PKEY* pkey = NULL;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = lwocryptx_key_allocate_keymaterial(key, 0) || lwocryptx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err);
    }

    if (key->keytype == KEY_TYPE_KEM) {
        ret = !lwocryptx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        ret = lwocryptx_key_gen_lwocrypt(key, 1);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM || key->keytype == KEY_TYPE_HYB_SIG) {
        pkey = lwocryptx_key_gen_evp_key(key->lwocryptx_provider_ctx.lwocryptx_evp_ctx, key->pubkey, key->privkey);
        ON_ERR_GOTO(pkey==NULL, err);
        ret = !lwocryptx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        LWOCRYPT_KEY_PRINTF3("LWOCRYPTKM: LWOCRYPTX_KEY privkeylen %ld & pubkeylen: %ld\n", key->privkeylen, key->pubkeylen);

        if (key->keytype == KEY_TYPE_HYB_SIG) {
           key->classical_pkey = pkey;
           ret = lwocryptx_key_gen_lwocrypt(key, 0);
	}
	else {
           EVP_PKEY_free(pkey);
           ret = lwocryptx_key_gen_lwocrypt(key, 1);
	}
    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = !lwocryptx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        ret = lwocryptx_key_gen_lwocrypt(key, 0);
    } else {
        ret = 1;
    }
    err:
	if (ret) {
		EVP_PKEY_free(pkey);
		key->classical_pkey = NULL;
	}
    return ret;
}

int lwocryptx_key_secbits(LWOCRYPTX_KEY *key) {
    return key->bit_security;
}

int lwocryptx_key_maxsize(LWOCRYPTX_KEY *key) {
    switch(key->keytype) {
    case KEY_TYPE_KEM:
	return key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_ECX_HYB_KEM:
	return key->lwocryptx_provider_ctx.lwocryptx_evp_ctx->evp_info->kex_length_secret + key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_SIG:
	return key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_signature;
    case KEY_TYPE_HYB_SIG:
	return key->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_signature + key->lwocryptx_provider_ctx.lwocryptx_evp_ctx->evp_info->length_signature+SIZE_OF_UINT32;
    default:
	LWOCRYPT_KEY_PRINTF("LWOCRYPTX KEY: Wrong key type\n");
	return 0;
    }
}

int lwocryptx_key_get_lwocrypt_public_key_len(LWOCRYPTX_KEY *k) {
    switch(k->keytype) {
        case KEY_TYPE_SIG:
	case KEY_TYPE_KEM:
	    return k->pubkeylen;
	case KEY_TYPE_HYB_SIG:
	    return k->lwocryptx_provider_ctx.lwocryptx_qs_ctx.sig->length_public_key;
	case KEY_TYPE_ECX_HYB_KEM:
	case KEY_TYPE_ECP_HYB_KEM:
	    return k->lwocryptx_provider_ctx.lwocryptx_qs_ctx.kem->length_public_key;
        default:
            LWOCRYPT_KEY_PRINTF2("LWOCRYPTX_KEY: Unknown key type encountered: %d\n", k->keytype);
	    return -1;
    }
}
