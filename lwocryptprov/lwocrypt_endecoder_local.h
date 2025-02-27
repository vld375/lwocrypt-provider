// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * LWOCRYPT OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL endecoder.
 *
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include "lwocrypt_prov.h"

OSSL_FUNC_keymgmt_new_fn *lwocrypt_prov_get_keymgmt_new(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_free_fn *lwocrypt_prov_get_keymgmt_free(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_import_fn *lwocrypt_prov_get_keymgmt_import(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_export_fn *lwocrypt_prov_get_keymgmt_export(const OSSL_DISPATCH *fns);

int lwocrypt_prov_der_from_p8(unsigned char **new_der, long *new_der_len,
                          unsigned char *input_der, long input_der_len,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg);

void *lwocrypt_prov_import_key(const OSSL_DISPATCH *fns, void *provctx,
                           int selection, const OSSL_PARAM params[]);
void lwocrypt_prov_free_key(const OSSL_DISPATCH *fns, void *key);
int lwocrypt_read_der(PROV_LWOCRYPT_CTX *provctx, OSSL_CORE_BIO *cin,  unsigned char **data,
                  long *len);
