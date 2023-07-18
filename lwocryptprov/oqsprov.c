// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * LWOCRYPT OpenSSL 3 provider
 * 
 * Code strongly inspired by OpenSSL legacy provider.
 *
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include "lwocrypt_prov.h"

#ifdef NDEBUG
#define LWOCRYPT_PROV_PRINTF(a)
#define LWOCRYPT_PROV_PRINTF2(a, b)
#define LWOCRYPT_PROV_PRINTF3(a, b, c)
#else
#define LWOCRYPT_PROV_PRINTF(a) if (getenv("LWOCRYPTPROV")) printf(a)
#define LWOCRYPT_PROV_PRINTF2(a, b) if (getenv("LWOCRYPTPROV")) printf(a, b)
#define LWOCRYPT_PROV_PRINTF3(a, b, c) if (getenv("LWOCRYPTPROV")) printf(a, b, c)
#endif // NDEBUG

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn lwocryptprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn lwocryptprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn lwocryptprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn lwocrypt_provider_get_capabilities;

/* 
 * List of all algorithms with given OIDs
 */
///// LWOCRYPT_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START
#define LWOCRYPT_OID_CNT 46
const char* lwocrypt_oid_alg_list[LWOCRYPT_OID_CNT] =
{
"1.3.6.1.4.1.2.267.7.4.4", "dilithium2",
"1.3.9999.2.7.1" , "p256_dilithium2",
"1.3.9999.2.7.2" , "rsa3072_dilithium2",
"1.3.6.1.4.1.2.267.7.6.5", "dilithium3",
"1.3.9999.2.7.3" , "p384_dilithium3",
"1.3.6.1.4.1.2.267.7.8.7", "dilithium5",
"1.3.9999.2.7.4" , "p521_dilithium5",
"1.3.9999.3.6", "falcon512",
"1.3.9999.3.7" , "p256_falcon512",
"1.3.9999.3.8" , "rsa3072_falcon512",
"1.3.9999.3.9", "falcon1024",
"1.3.9999.3.10" , "p521_falcon1024",
"1.3.9999.6.4.13", "sphincssha2128fsimple",
"1.3.9999.6.4.14" , "p256_sphincssha2128fsimple",
"1.3.9999.6.4.15" , "rsa3072_sphincssha2128fsimple",
"1.3.9999.6.4.16", "sphincssha2128ssimple",
"1.3.9999.6.4.17" , "p256_sphincssha2128ssimple",
"1.3.9999.6.4.18" , "rsa3072_sphincssha2128ssimple",
"1.3.9999.6.5.10", "sphincssha2192fsimple",
"1.3.9999.6.5.11" , "p384_sphincssha2192fsimple",
"1.3.9999.6.7.13", "sphincsshake128fsimple",
"1.3.9999.6.7.14" , "p256_sphincsshake128fsimple",
"1.3.9999.6.7.15" , "rsa3072_sphincsshake128fsimple",
///// LWOCRYPT_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

int lwocrypt_patch_oids(void) {
///// LWOCRYPT_TEMPLATE_FRAGMENT_OID_PATCHING_START
   if (getenv("LWOCRYPT_OID_DILITHIUM2")) lwocrypt_oid_alg_list[0] = getenv("LWOCRYPT_OID_DILITHIUM2");
   if (getenv("LWOCRYPT_OID_P256_DILITHIUM2")) lwocrypt_oid_alg_list[2] = getenv("LWOCRYPT_OID_P256_DILITHIUM2");
   if (getenv("LWOCRYPT_OID_RSA3072_DILITHIUM2")) lwocrypt_oid_alg_list[4] = getenv("LWOCRYPT_OID_RSA3072_DILITHIUM2");
   if (getenv("LWOCRYPT_OID_DILITHIUM3")) lwocrypt_oid_alg_list[6] = getenv("LWOCRYPT_OID_DILITHIUM3");
   if (getenv("LWOCRYPT_OID_P384_DILITHIUM3")) lwocrypt_oid_alg_list[8] = getenv("LWOCRYPT_OID_P384_DILITHIUM3");
   if (getenv("LWOCRYPT_OID_DILITHIUM5")) lwocrypt_oid_alg_list[10] = getenv("LWOCRYPT_OID_DILITHIUM5");
   if (getenv("LWOCRYPT_OID_P521_DILITHIUM5")) lwocrypt_oid_alg_list[12] = getenv("LWOCRYPT_OID_P521_DILITHIUM5");
   if (getenv("LWOCRYPT_OID_FALCON512")) lwocrypt_oid_alg_list[14] = getenv("LWOCRYPT_OID_FALCON512");
   if (getenv("LWOCRYPT_OID_P256_FALCON512")) lwocrypt_oid_alg_list[16] = getenv("LWOCRYPT_OID_P256_FALCON512");
   if (getenv("LWOCRYPT_OID_RSA3072_FALCON512")) lwocrypt_oid_alg_list[18] = getenv("LWOCRYPT_OID_RSA3072_FALCON512");
   if (getenv("LWOCRYPT_OID_FALCON1024")) lwocrypt_oid_alg_list[20] = getenv("LWOCRYPT_OID_FALCON1024");
   if (getenv("LWOCRYPT_OID_P521_FALCON1024")) lwocrypt_oid_alg_list[22] = getenv("LWOCRYPT_OID_P521_FALCON1024");
   if (getenv("LWOCRYPT_OID_SPHINCSSHA2128FSIMPLE")) lwocrypt_oid_alg_list[24] = getenv("LWOCRYPT_OID_SPHINCSSHA2128FSIMPLE");
   if (getenv("LWOCRYPT_OID_P256_SPHINCSSHA2128FSIMPLE")) lwocrypt_oid_alg_list[26] = getenv("LWOCRYPT_OID_P256_SPHINCSSHA2128FSIMPLE");
   if (getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHA2128FSIMPLE")) lwocrypt_oid_alg_list[28] = getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHA2128FSIMPLE");
   if (getenv("LWOCRYPT_OID_SPHINCSSHA2128SSIMPLE")) lwocrypt_oid_alg_list[30] = getenv("LWOCRYPT_OID_SPHINCSSHA2128SSIMPLE");
   if (getenv("LWOCRYPT_OID_P256_SPHINCSSHA2128SSIMPLE")) lwocrypt_oid_alg_list[32] = getenv("LWOCRYPT_OID_P256_SPHINCSSHA2128SSIMPLE");
   if (getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHA2128SSIMPLE")) lwocrypt_oid_alg_list[34] = getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHA2128SSIMPLE");
   if (getenv("LWOCRYPT_OID_SPHINCSSHA2192FSIMPLE")) lwocrypt_oid_alg_list[36] = getenv("LWOCRYPT_OID_SPHINCSSHA2192FSIMPLE");
   if (getenv("LWOCRYPT_OID_P384_SPHINCSSHA2192FSIMPLE")) lwocrypt_oid_alg_list[38] = getenv("LWOCRYPT_OID_P384_SPHINCSSHA2192FSIMPLE");
   if (getenv("LWOCRYPT_OID_SPHINCSSHAKE128FSIMPLE")) lwocrypt_oid_alg_list[40] = getenv("LWOCRYPT_OID_SPHINCSSHAKE128FSIMPLE");
   if (getenv("LWOCRYPT_OID_P256_SPHINCSSHAKE128FSIMPLE")) lwocrypt_oid_alg_list[42] = getenv("LWOCRYPT_OID_P256_SPHINCSSHAKE128FSIMPLE");
   if (getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHAKE128FSIMPLE")) lwocrypt_oid_alg_list[44] = getenv("LWOCRYPT_OID_RSA3072_SPHINCSSHAKE128FSIMPLE");
///// LWOCRYPT_TEMPLATE_FRAGMENT_OID_PATCHING_END
    return 1;
}


#ifdef USE_ENCODING_LIB
const char* lwocrypt_alg_encoding_list[LWOCRYPT_OID_CNT] = { 0 };

int lwocrypt_patch_encodings(void) {
///// LWOCRYPT_TEMPLATE_FRAGMENT_ENCODING_PATCHING_START
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM2")) lwocrypt_alg_encoding_list[0] = getenv("LWOCRYPT_ENCODING_DILITHIUM2"); 
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM2_ALGNAME")) lwocrypt_alg_encoding_list[1] = getenv("LWOCRYPT_ENCODING_DILITHIUM2_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P256_DILITHIUM2")) lwocrypt_alg_encoding_list[2] = getenv("LWOCRYPT_ENCODING_P256_DILITHIUM2"); 
   if (getenv("LWOCRYPT_ENCODING_P256_DILITHIUM2_ALGNAME")) lwocrypt_alg_encoding_list[3] = getenv("LWOCRYPT_ENCODING_P256_DILITHIUM2_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_RSA3072_DILITHIUM2")) lwocrypt_alg_encoding_list[4] = getenv("LWOCRYPT_ENCODING_RSA3072_DILITHIUM2"); 
   if (getenv("LWOCRYPT_ENCODING_RSA3072_DILITHIUM2_ALGNAME")) lwocrypt_alg_encoding_list[5] = getenv("LWOCRYPT_ENCODING_RSA3072_DILITHIUM2_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM3")) lwocrypt_alg_encoding_list[6] = getenv("LWOCRYPT_ENCODING_DILITHIUM3"); 
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM3_ALGNAME")) lwocrypt_alg_encoding_list[7] = getenv("LWOCRYPT_ENCODING_DILITHIUM3_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P384_DILITHIUM3")) lwocrypt_alg_encoding_list[8] = getenv("LWOCRYPT_ENCODING_P384_DILITHIUM3"); 
   if (getenv("LWOCRYPT_ENCODING_P384_DILITHIUM3_ALGNAME")) lwocrypt_alg_encoding_list[9] = getenv("LWOCRYPT_ENCODING_P384_DILITHIUM3_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM5")) lwocrypt_alg_encoding_list[10] = getenv("LWOCRYPT_ENCODING_DILITHIUM5"); 
   if (getenv("LWOCRYPT_ENCODING_DILITHIUM5_ALGNAME")) lwocrypt_alg_encoding_list[11] = getenv("LWOCRYPT_ENCODING_DILITHIUM5_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P521_DILITHIUM5")) lwocrypt_alg_encoding_list[12] = getenv("LWOCRYPT_ENCODING_P521_DILITHIUM5"); 
   if (getenv("LWOCRYPT_ENCODING_P521_DILITHIUM5_ALGNAME")) lwocrypt_alg_encoding_list[13] = getenv("LWOCRYPT_ENCODING_P521_DILITHIUM5_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_FALCON512")) lwocrypt_alg_encoding_list[14] = getenv("LWOCRYPT_ENCODING_FALCON512"); 
   if (getenv("LWOCRYPT_ENCODING_FALCON512_ALGNAME")) lwocrypt_alg_encoding_list[15] = getenv("LWOCRYPT_ENCODING_FALCON512_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P256_FALCON512")) lwocrypt_alg_encoding_list[16] = getenv("LWOCRYPT_ENCODING_P256_FALCON512"); 
   if (getenv("LWOCRYPT_ENCODING_P256_FALCON512_ALGNAME")) lwocrypt_alg_encoding_list[17] = getenv("LWOCRYPT_ENCODING_P256_FALCON512_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_RSA3072_FALCON512")) lwocrypt_alg_encoding_list[18] = getenv("LWOCRYPT_ENCODING_RSA3072_FALCON512"); 
   if (getenv("LWOCRYPT_ENCODING_RSA3072_FALCON512_ALGNAME")) lwocrypt_alg_encoding_list[19] = getenv("LWOCRYPT_ENCODING_RSA3072_FALCON512_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_FALCON1024")) lwocrypt_alg_encoding_list[20] = getenv("LWOCRYPT_ENCODING_FALCON1024"); 
   if (getenv("LWOCRYPT_ENCODING_FALCON1024_ALGNAME")) lwocrypt_alg_encoding_list[21] = getenv("LWOCRYPT_ENCODING_FALCON1024_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P521_FALCON1024")) lwocrypt_alg_encoding_list[22] = getenv("LWOCRYPT_ENCODING_P521_FALCON1024"); 
   if (getenv("LWOCRYPT_ENCODING_P521_FALCON1024_ALGNAME")) lwocrypt_alg_encoding_list[23] = getenv("LWOCRYPT_ENCODING_P521_FALCON1024_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128FSIMPLE")) lwocrypt_alg_encoding_list[24] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[25] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128FSIMPLE")) lwocrypt_alg_encoding_list[26] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[27] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE")) lwocrypt_alg_encoding_list[28] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[29] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128SSIMPLE")) lwocrypt_alg_encoding_list[30] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128SSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128SSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[31] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2128SSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128SSIMPLE")) lwocrypt_alg_encoding_list[32] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128SSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128SSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[33] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHA2128SSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE")) lwocrypt_alg_encoding_list[34] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[35] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2192FSIMPLE")) lwocrypt_alg_encoding_list[36] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2192FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHA2192FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[37] = getenv("LWOCRYPT_ENCODING_SPHINCSSHA2192FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P384_SPHINCSSHA2192FSIMPLE")) lwocrypt_alg_encoding_list[38] = getenv("LWOCRYPT_ENCODING_P384_SPHINCSSHA2192FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_P384_SPHINCSSHA2192FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[39] = getenv("LWOCRYPT_ENCODING_P384_SPHINCSSHA2192FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHAKE128FSIMPLE")) lwocrypt_alg_encoding_list[40] = getenv("LWOCRYPT_ENCODING_SPHINCSSHAKE128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_SPHINCSSHAKE128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[41] = getenv("LWOCRYPT_ENCODING_SPHINCSSHAKE128FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHAKE128FSIMPLE")) lwocrypt_alg_encoding_list[42] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHAKE128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHAKE128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[43] = getenv("LWOCRYPT_ENCODING_P256_SPHINCSSHAKE128FSIMPLE_ALGNAME");
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE")) lwocrypt_alg_encoding_list[44] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE"); 
   if (getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE_ALGNAME")) lwocrypt_alg_encoding_list[45] = getenv("LWOCRYPT_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE_ALGNAME");
///// LWOCRYPT_TEMPLATE_FRAGMENT_ENCODING_PATCHING_END
    return 1;
}
#endif

#define SIGALG(NAMES, SECBITS, FUNC) { NAMES, "provider=lwocryptprovider,lwocryptprovider.security_bits="#SECBITS"", FUNC }
#define KEMBASEALG(NAMES, SECBITS) \
    { "" #NAMES "", "provider=lwocryptprovider,lwocryptprovider.security_bits="#SECBITS"", lwocrypt_generic_kem_functions },

#define KEMHYBALG(NAMES, SECBITS) \
    { "" #NAMES "", "provider=lwocryptprovider,lwocryptprovider.security_bits="#SECBITS"", lwocrypt_hybrid_kem_functions },

#define KEMKMALG(NAMES, SECBITS) \
    { "" #NAMES "", "provider=lwocryptprovider,lwocryptprovider.security_bits="#SECBITS"" , lwocrypt_##NAMES##_keymgmt_functions },

#define KEMKMHYBALG(NAMES, SECBITS, HYBTYPE) \
    { "" #NAMES "", "provider=lwocryptprovider,lwocryptprovider.security_bits="#SECBITS"" , lwocrypt_##HYBTYPE##_##NAMES##_keymgmt_functions },

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM lwocryptprovider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};


static const OSSL_ALGORITHM lwocryptprovider_signatures[] = {
///// LWOCRYPT_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, lwocrypt_signature_functions),
    SIGALG("p256_dilithium2", 128, lwocrypt_signature_functions),
    SIGALG("rsa3072_dilithium2", 128, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, lwocrypt_signature_functions),
    SIGALG("p384_dilithium3", 192, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, lwocrypt_signature_functions),
    SIGALG("p521_dilithium5", 256, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, lwocrypt_signature_functions),
    SIGALG("p256_falcon512", 128, lwocrypt_signature_functions),
    SIGALG("rsa3072_falcon512", 128, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, lwocrypt_signature_functions),
    SIGALG("p521_falcon1024", 256, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, lwocrypt_signature_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, lwocrypt_signature_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, lwocrypt_signature_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, lwocrypt_signature_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, lwocrypt_signature_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, lwocrypt_signature_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, lwocrypt_signature_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, lwocrypt_signature_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, lwocrypt_signature_functions),
#endif
///// LWOCRYPT_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lwocryptprovider_asym_kems[] = {
///// LWOCRYPT_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_640_aes
    KEMBASEALG(frodo640aes, 128)
    KEMHYBALG(p256_frodo640aes, 128)
    KEMHYBALG(x25519_frodo640aes, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_640_shake
    KEMBASEALG(frodo640shake, 128)
    KEMHYBALG(p256_frodo640shake, 128)
    KEMHYBALG(x25519_frodo640shake, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_976_aes
    KEMBASEALG(frodo976aes, 192)
    KEMHYBALG(p384_frodo976aes, 192)
    KEMHYBALG(x448_frodo976aes, 192)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_976_shake
    KEMBASEALG(frodo976shake, 192)
    KEMHYBALG(p384_frodo976shake, 192)
    KEMHYBALG(x448_frodo976shake, 192)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_1344_aes
    KEMBASEALG(frodo1344aes, 256)
    KEMHYBALG(p521_frodo1344aes, 256)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_1344_shake
    KEMBASEALG(frodo1344shake, 256)
    KEMHYBALG(p521_frodo1344shake, 256)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_512
    KEMBASEALG(kyber512, 128)
    KEMHYBALG(p256_kyber512, 128)
    KEMHYBALG(x25519_kyber512, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_768
    KEMBASEALG(kyber768, 192)
    KEMHYBALG(p384_kyber768, 192)
    KEMHYBALG(x448_kyber768, 192)
    KEMHYBALG(x25519_kyber768, 128)
    KEMHYBALG(p256_kyber768, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_1024
    KEMBASEALG(kyber1024, 256)
    KEMHYBALG(p521_kyber1024, 256)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l1
    KEMBASEALG(bikel1, 128)
    KEMHYBALG(p256_bikel1, 128)
    KEMHYBALG(x25519_bikel1, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l3
    KEMBASEALG(bikel3, 192)
    KEMHYBALG(p384_bikel3, 192)
    KEMHYBALG(x448_bikel3, 192)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l5
    KEMBASEALG(bikel5, 256)
    KEMHYBALG(p521_bikel5, 256)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_128
    KEMBASEALG(hqc128, 128)
    KEMHYBALG(p256_hqc128, 128)
    KEMHYBALG(x25519_hqc128, 128)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_192
    KEMBASEALG(hqc192, 192)
    KEMHYBALG(p384_hqc192, 192)
    KEMHYBALG(x448_hqc192, 192)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_256
    KEMBASEALG(hqc256, 256)
    KEMHYBALG(p521_hqc256, 256)
#endif
///// LWOCRYPT_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lwocryptprovider_keymgmt[] = {
///// LWOCRYPT_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, lwocrypt_dilithium2_keymgmt_functions),
    SIGALG("p256_dilithium2", 128, lwocrypt_p256_dilithium2_keymgmt_functions),
    SIGALG("rsa3072_dilithium2", 128, lwocrypt_rsa3072_dilithium2_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, lwocrypt_dilithium3_keymgmt_functions),
    SIGALG("p384_dilithium3", 192, lwocrypt_p384_dilithium3_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, lwocrypt_dilithium5_keymgmt_functions),
    SIGALG("p521_dilithium5", 256, lwocrypt_p521_dilithium5_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, lwocrypt_falcon512_keymgmt_functions),
    SIGALG("p256_falcon512", 128, lwocrypt_p256_falcon512_keymgmt_functions),
    SIGALG("rsa3072_falcon512", 128, lwocrypt_rsa3072_falcon512_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, lwocrypt_falcon1024_keymgmt_functions),
    SIGALG("p521_falcon1024", 256, lwocrypt_p521_falcon1024_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, lwocrypt_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, lwocrypt_p256_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, lwocrypt_rsa3072_sphincssha2128fsimple_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, lwocrypt_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, lwocrypt_p256_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, lwocrypt_rsa3072_sphincssha2128ssimple_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, lwocrypt_sphincssha2192fsimple_keymgmt_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, lwocrypt_p384_sphincssha2192fsimple_keymgmt_functions),
#endif
#ifdef LWOCRYPT_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, lwocrypt_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, lwocrypt_p256_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, lwocrypt_rsa3072_sphincsshake128fsimple_keymgmt_functions),
#endif

#ifdef LWOCRYPT_ENABLE_KEM_frodokem_640_aes
    KEMKMALG(frodo640aes, 128)

    KEMKMHYBALG(p256_frodo640aes, 128, ecp)
    KEMKMHYBALG(x25519_frodo640aes, 128, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_640_shake
    KEMKMALG(frodo640shake, 128)

    KEMKMHYBALG(p256_frodo640shake, 128, ecp)
    KEMKMHYBALG(x25519_frodo640shake, 128, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_976_aes
    KEMKMALG(frodo976aes, 192)

    KEMKMHYBALG(p384_frodo976aes, 192, ecp)
    KEMKMHYBALG(x448_frodo976aes, 192, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_976_shake
    KEMKMALG(frodo976shake, 192)

    KEMKMHYBALG(p384_frodo976shake, 192, ecp)
    KEMKMHYBALG(x448_frodo976shake, 192, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_1344_aes
    KEMKMALG(frodo1344aes, 256)

    KEMKMHYBALG(p521_frodo1344aes, 256, ecp)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_frodokem_1344_shake
    KEMKMALG(frodo1344shake, 256)

    KEMKMHYBALG(p521_frodo1344shake, 256, ecp)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_512
    KEMKMALG(kyber512, 128)

    KEMKMHYBALG(p256_kyber512, 128, ecp)
    KEMKMHYBALG(x25519_kyber512, 128, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_768
    KEMKMALG(kyber768, 192)

    KEMKMHYBALG(p384_kyber768, 192, ecp)
    KEMKMHYBALG(x448_kyber768, 192, ecx)
    KEMKMHYBALG(x25519_kyber768, 128, ecx)
    KEMKMHYBALG(p256_kyber768, 128, ecp)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_kyber_1024
    KEMKMALG(kyber1024, 256)

    KEMKMHYBALG(p521_kyber1024, 256, ecp)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l1
    KEMKMALG(bikel1, 128)

    KEMKMHYBALG(p256_bikel1, 128, ecp)
    KEMKMHYBALG(x25519_bikel1, 128, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l3
    KEMKMALG(bikel3, 192)

    KEMKMHYBALG(p384_bikel3, 192, ecp)
    KEMKMHYBALG(x448_bikel3, 192, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_bike_l5
    KEMKMALG(bikel5, 256)

    KEMKMHYBALG(p521_bikel5, 256, ecp)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_128
    KEMKMALG(hqc128, 128)

    KEMKMHYBALG(p256_hqc128, 128, ecp)
    KEMKMHYBALG(x25519_hqc128, 128, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_192
    KEMKMALG(hqc192, 192)

    KEMKMHYBALG(p384_hqc192, 192, ecp)
    KEMKMHYBALG(x448_hqc192, 192, ecx)
#endif
#ifdef LWOCRYPT_ENABLE_KEM_hqc_256
    KEMKMALG(hqc256, 256)

    KEMKMHYBALG(p521_hqc256, 256, ecp)
#endif
///// LWOCRYPT_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    //ALG("x25519_sikep434", lwocrypt_ecx_sikep434_keymgmt_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lwocryptprovider_encoder[] = {
#define ENCODER_PROVIDER "lwocryptprovider"
#include "lwocryptencoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM lwocryptprovider_decoder[] = {
#define DECODER_PROVIDER "lwocryptprovider"
#include "lwocryptdecoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};


static const OSSL_PARAM *lwocryptprovider_gettable_params(void *provctx)
{
    return lwocryptprovider_param_types;
}

#define LWOCRYPT_PROVIDER_BASE_BUILD_INFO_STR "LWOCRYPT Provider v." LWOCRYPT_PROVIDER_VERSION_STR LWOCRYPT_PROVIDER_COMMIT " based on liblwocrypt v." LWOCRYPT_VERSION_TEXT

#ifdef QSC_ENCODING_VERSION_STRING
#define LWOCRYPT_PROVIDER_BUILD_INFO_STR LWOCRYPT_PROVIDER_BASE_BUILD_INFO_STR " using qsc-key-encoder v." QSC_ENCODING_VERSION_STRING
#else
#define LWOCRYPT_PROVIDER_BUILD_INFO_STR LWOCRYPT_PROVIDER_BASE_BUILD_INFO_STR
#endif


static int lwocryptprovider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL LWOCRYPT Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, LWOCRYPT_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, LWOCRYPT_PROVIDER_BUILD_INFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) // provider is always running
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *lwocryptprovider_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return lwocryptprovider_signatures;
    case OSSL_OP_KEM:
        return lwocryptprovider_asym_kems;
    case OSSL_OP_KEYMGMT:
        return lwocryptprovider_keymgmt;
    case OSSL_OP_ENCODER:
        return lwocryptprovider_encoder;
    case OSSL_OP_DECODER:
        return lwocryptprovider_decoder;
    default:
        if (getenv("LWOCRYPTPROV")) printf("Unknown operation %d requested from LWOCRYPT provider\n", operation_id);
    }
    return NULL;
}

static void lwocryptprovider_teardown(void *provctx)
{
   lwocryptx_freeprovctx((PROV_LWOCRYPT_CTX*)provctx);
   LWOCRYPT_destroy();
}

/* Functions we provide to the core */
static const OSSL_DISPATCH lwocryptprovider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))lwocryptprovider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))lwocryptprovider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))lwocryptprovider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))lwocryptprovider_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))lwocrypt_provider_get_capabilities },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const OSSL_DISPATCH *orig_in=in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create= NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid= NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;

    LWOCRYPT_init();

    if (!lwocrypt_prov_bio_from_dispatch(in))
        return 0;

    if (!lwocrypt_patch_codepoints())
        return 0;

    if (!lwocrypt_patch_oids())
        return 0;

#ifdef USE_ENCODING_LIB
    if (!lwocrypt_patch_encodings())
        return 0;
#endif

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid==NULL)
        return 0;

    // insert all OIDs to the global objects list
    for (i=0; i<LWOCRYPT_OID_CNT;i+=2) {
        if (!c_obj_create(handle, lwocrypt_oid_alg_list[i], lwocrypt_oid_alg_list[i+1], lwocrypt_oid_alg_list[i+1])) {
                ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_OBJ_CREATE_ERR);
                fprintf(stderr, "error registering NID for %s\n", lwocrypt_oid_alg_list[i+1]);
                return 0;
        }

        if (!lwocrypt_set_nid((char*)lwocrypt_oid_alg_list[i+1], OBJ_sn2nid(lwocrypt_oid_alg_list[i+1]))) {
              ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_OBJ_CREATE_ERR);
              return 0;
        }

        if (!c_obj_add_sigid(handle, lwocrypt_oid_alg_list[i+1], "", lwocrypt_oid_alg_list[i+1])) {
              fprintf(stderr, "error registering %s with no hash\n", lwocrypt_oid_alg_list[i+1]);
              ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_OBJ_CREATE_ERR);
              return 0;
        }

        if (OBJ_sn2nid(lwocrypt_oid_alg_list[i+1]) != 0) {
            LWOCRYPT_PROV_PRINTF3("LWOCRYPT PROV: successfully registered %s with NID %d\n", lwocrypt_oid_alg_list[i+1], OBJ_sn2nid(lwocrypt_oid_alg_list[i+1]));
        }
        else {
            fprintf(stderr, "LWOCRYPT PROV: Impossible error: NID unregistered for %s.\n", lwocrypt_oid_alg_list[i+1]);
            return 0;
        }
            
    }

    // if libctx not yet existing, create a new one
    if ( ((corebiometh = lwocrypt_bio_prov_init_bio_method()) == NULL) ||
         ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
         ((*provctx = lwocryptx_newprovctx(libctx, handle, corebiometh)) == NULL ) ) { 
        LWOCRYPT_PROV_PRINTF("LWOCRYPT PROV: error creating new provider context\n");
        ERR_raise(ERR_LIB_USER, LWOCRYPTPROV_R_LIB_CREATE_ERR);
        goto end_init;
    }

    *out = lwocryptprovider_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default") && !OSSL_PROVIDER_available(libctx, "fips")) {
        LWOCRYPT_PROV_PRINTF("LWOCRYPT PROV: Default and FIPS provider not available. Errors may result.\n");
    }
    else {
        LWOCRYPT_PROV_PRINTF("LWOCRYPT PROV: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        OSSL_LIB_CTX_free(libctx);
        lwocryptprovider_teardown(*provctx);
        *provctx = NULL;
    }
    return rc;
}
