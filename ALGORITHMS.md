Algorithms supported
====================

This page lists all quantum-safe algorithms supported by lwocrypt-provider.

Some algorithms by default may not be enabled for use in the master code-generator template file.

As standardization for these algorithms within TLS is not done, all TLS code points/IDs can be changed from their default values to values set by environment variables. This facilitates interoperability testing with TLS1.3 implementations that use different IDs.

# Code points / algorithm IDs

<!--- LWOCRYPT_TEMPLATE_FRAGMENT_IDS_START -->
|Algorithm name | default ID | enabled | environment variable |
|---------------|:----------:|:-------:|----------------------|
| frodo640aes | 0x0200 | Yes | LWOCRYPT_CODEPOINT_FRODO640AES |
| p256_frodo640aes | 0x2F00 | Yes | LWOCRYPT_CODEPOINT_P256_FRODO640AES |
| x25519_frodo640aes | 0x2F80 | Yes | LWOCRYPT_CODEPOINT_X25519_FRODO640AES |
| frodo640shake | 0x0201 | Yes | LWOCRYPT_CODEPOINT_FRODO640SHAKE |
| p256_frodo640shake | 0x2F01 | Yes | LWOCRYPT_CODEPOINT_P256_FRODO640SHAKE |
| x25519_frodo640shake | 0x2F81 | Yes | LWOCRYPT_CODEPOINT_X25519_FRODO640SHAKE |
| frodo976aes | 0x0202 | Yes | LWOCRYPT_CODEPOINT_FRODO976AES |
| p384_frodo976aes | 0x2F02 | Yes | LWOCRYPT_CODEPOINT_P384_FRODO976AES |
| x448_frodo976aes | 0x2F82 | Yes | LWOCRYPT_CODEPOINT_X448_FRODO976AES |
| frodo976shake | 0x0203 | Yes | LWOCRYPT_CODEPOINT_FRODO976SHAKE |
| p384_frodo976shake | 0x2F03 | Yes | LWOCRYPT_CODEPOINT_P384_FRODO976SHAKE |
| x448_frodo976shake | 0x2F83 | Yes | LWOCRYPT_CODEPOINT_X448_FRODO976SHAKE |
| frodo1344aes | 0x0204 | Yes | LWOCRYPT_CODEPOINT_FRODO1344AES |
| p521_frodo1344aes | 0x2F04 | Yes | LWOCRYPT_CODEPOINT_P521_FRODO1344AES |
| frodo1344shake | 0x0205 | Yes | LWOCRYPT_CODEPOINT_FRODO1344SHAKE |
| p521_frodo1344shake | 0x2F05 | Yes | LWOCRYPT_CODEPOINT_P521_FRODO1344SHAKE |
| kyber512 | 0x023A | Yes | LWOCRYPT_CODEPOINT_KYBER512 |
| p256_kyber512 | 0x2F3A | Yes | LWOCRYPT_CODEPOINT_P256_KYBER512 |
| x25519_kyber512 | 0x2F39 | Yes | LWOCRYPT_CODEPOINT_X25519_KYBER512 |
| kyber768 | 0x023C | Yes | LWOCRYPT_CODEPOINT_KYBER768 |
| p384_kyber768 | 0x2F3C | Yes | LWOCRYPT_CODEPOINT_P384_KYBER768 |
| x448_kyber768 | 0x2F90 | Yes | LWOCRYPT_CODEPOINT_X448_KYBER768 |
| x25519_kyber768 | 0x6399 | Yes | LWOCRYPT_CODEPOINT_X25519_KYBER768 |
| p256_kyber768 | 0x639A | Yes | LWOCRYPT_CODEPOINT_P256_KYBER768 |
| kyber1024 | 0x023D | Yes | LWOCRYPT_CODEPOINT_KYBER1024 |
| p521_kyber1024 | 0x2F3D | Yes | LWOCRYPT_CODEPOINT_P521_KYBER1024 |
| bikel1 | 0x0241 | Yes | LWOCRYPT_CODEPOINT_BIKEL1 |
| p256_bikel1 | 0x2F41 | Yes | LWOCRYPT_CODEPOINT_P256_BIKEL1 |
| x25519_bikel1 | 0x2FAE | Yes | LWOCRYPT_CODEPOINT_X25519_BIKEL1 |
| bikel3 | 0x0242 | Yes | LWOCRYPT_CODEPOINT_BIKEL3 |
| p384_bikel3 | 0x2F42 | Yes | LWOCRYPT_CODEPOINT_P384_BIKEL3 |
| x448_bikel3 | 0x2FAF | Yes | LWOCRYPT_CODEPOINT_X448_BIKEL3 |
| bikel5 | 0x0243 | Yes | LWOCRYPT_CODEPOINT_BIKEL5 |
| p521_bikel5 | 0x2F43 | Yes | LWOCRYPT_CODEPOINT_P521_BIKEL5 |
| hqc128 | 0x022C | Yes | LWOCRYPT_CODEPOINT_HQC128 |
| p256_hqc128 | 0x2F2C | Yes | LWOCRYPT_CODEPOINT_P256_HQC128 |
| x25519_hqc128 | 0x2FAC | Yes | LWOCRYPT_CODEPOINT_X25519_HQC128 |
| hqc192 | 0x022D | Yes | LWOCRYPT_CODEPOINT_HQC192 |
| p384_hqc192 | 0x2F2D | Yes | LWOCRYPT_CODEPOINT_P384_HQC192 |
| x448_hqc192 | 0x2FAD | Yes | LWOCRYPT_CODEPOINT_X448_HQC192 |
| hqc256 | 0x022E | Yes | LWOCRYPT_CODEPOINT_HQC256 |
| p521_hqc256 | 0x2F2E | Yes | LWOCRYPT_CODEPOINT_P521_HQC256 |
| dilithium2 | 0xfea0 |Yes| LWOCRYPT_CODEPOINT_DILITHIUM2
| p256_dilithium2 | 0xfea1 |Yes| LWOCRYPT_CODEPOINT_P256_DILITHIUM2
| rsa3072_dilithium2 | 0xfea2 |Yes| LWOCRYPT_CODEPOINT_RSA3072_DILITHIUM2
| dilithium3 | 0xfea3 |Yes| LWOCRYPT_CODEPOINT_DILITHIUM3
| p384_dilithium3 | 0xfea4 |Yes| LWOCRYPT_CODEPOINT_P384_DILITHIUM3
| dilithium5 | 0xfea5 |Yes| LWOCRYPT_CODEPOINT_DILITHIUM5
| p521_dilithium5 | 0xfea6 |Yes| LWOCRYPT_CODEPOINT_P521_DILITHIUM5
| falcon512 | 0xfeae |Yes| LWOCRYPT_CODEPOINT_FALCON512
| p256_falcon512 | 0xfeaf |Yes| LWOCRYPT_CODEPOINT_P256_FALCON512
| rsa3072_falcon512 | 0xfeb0 |Yes| LWOCRYPT_CODEPOINT_RSA3072_FALCON512
| falcon1024 | 0xfeb1 |Yes| LWOCRYPT_CODEPOINT_FALCON1024
| p521_falcon1024 | 0xfeb2 |Yes| LWOCRYPT_CODEPOINT_P521_FALCON1024
| sphincssha2128fsimple | 0xfeb3 |Yes| LWOCRYPT_CODEPOINT_SPHINCSSHA2128FSIMPLE
| p256_sphincssha2128fsimple | 0xfeb4 |Yes| LWOCRYPT_CODEPOINT_P256_SPHINCSSHA2128FSIMPLE
| rsa3072_sphincssha2128fsimple | 0xfeb5 |Yes| LWOCRYPT_CODEPOINT_RSA3072_SPHINCSSHA2128FSIMPLE
| sphincssha2128ssimple | 0xfeb6 |Yes| LWOCRYPT_CODEPOINT_SPHINCSSHA2128SSIMPLE
| p256_sphincssha2128ssimple | 0xfeb7 |Yes| LWOCRYPT_CODEPOINT_P256_SPHINCSSHA2128SSIMPLE
| rsa3072_sphincssha2128ssimple | 0xfeb8 |Yes| LWOCRYPT_CODEPOINT_RSA3072_SPHINCSSHA2128SSIMPLE
| sphincssha2192fsimple | 0xfeb9 |Yes| LWOCRYPT_CODEPOINT_SPHINCSSHA2192FSIMPLE
| p384_sphincssha2192fsimple | 0xfeba |Yes| LWOCRYPT_CODEPOINT_P384_SPHINCSSHA2192FSIMPLE
| sphincssha2192ssimple | 0xfebb |No| LWOCRYPT_CODEPOINT_SPHINCSSHA2192SSIMPLE
| p384_sphincssha2192ssimple | 0xfebc |No| LWOCRYPT_CODEPOINT_P384_SPHINCSSHA2192SSIMPLE
| sphincssha2256fsimple | 0xfebd |No| LWOCRYPT_CODEPOINT_SPHINCSSHA2256FSIMPLE
| p521_sphincssha2256fsimple | 0xfebe |No| LWOCRYPT_CODEPOINT_P521_SPHINCSSHA2256FSIMPLE
| sphincssha2256ssimple | 0xfec0 |No| LWOCRYPT_CODEPOINT_SPHINCSSHA2256SSIMPLE
| p521_sphincssha2256ssimple | 0xfec1 |No| LWOCRYPT_CODEPOINT_P521_SPHINCSSHA2256SSIMPLE
| sphincsshake128fsimple | 0xfec2 |Yes| LWOCRYPT_CODEPOINT_SPHINCSSHAKE128FSIMPLE
| p256_sphincsshake128fsimple | 0xfec3 |Yes| LWOCRYPT_CODEPOINT_P256_SPHINCSSHAKE128FSIMPLE
| rsa3072_sphincsshake128fsimple | 0xfec4 |Yes| LWOCRYPT_CODEPOINT_RSA3072_SPHINCSSHAKE128FSIMPLE
| sphincsshake128ssimple | 0xfec5 |No| LWOCRYPT_CODEPOINT_SPHINCSSHAKE128SSIMPLE
| p256_sphincsshake128ssimple | 0xfec6 |No| LWOCRYPT_CODEPOINT_P256_SPHINCSSHAKE128SSIMPLE
| rsa3072_sphincsshake128ssimple | 0xfec7 |No| LWOCRYPT_CODEPOINT_RSA3072_SPHINCSSHAKE128SSIMPLE
| sphincsshake192fsimple | 0xfec8 |No| LWOCRYPT_CODEPOINT_SPHINCSSHAKE192FSIMPLE
| p384_sphincsshake192fsimple | 0xfec9 |No| LWOCRYPT_CODEPOINT_P384_SPHINCSSHAKE192FSIMPLE
| sphincsshake192ssimple | 0xfeca |No| LWOCRYPT_CODEPOINT_SPHINCSSHAKE192SSIMPLE
| p384_sphincsshake192ssimple | 0xfecb |No| LWOCRYPT_CODEPOINT_P384_SPHINCSSHAKE192SSIMPLE
| sphincsshake256fsimple | 0xfecc |No| LWOCRYPT_CODEPOINT_SPHINCSSHAKE256FSIMPLE
| p521_sphincsshake256fsimple | 0xfecd |No| LWOCRYPT_CODEPOINT_P521_SPHINCSSHAKE256FSIMPLE
| sphincsshake256ssimple | 0xfece |No| LWOCRYPT_CODEPOINT_SPHINCSSHAKE256SSIMPLE
| p521_sphincsshake256ssimple | 0xfecf |No| LWOCRYPT_CODEPOINT_P521_SPHINCSSHAKE256SSIMPLE
<!--- LWOCRYPT_TEMPLATE_FRAGMENT_IDS_END -->

Changing code points
--------------------

In order to dynamically change the code point of any one algorithm, the respective
environment variable listed above has to be set to the `INT`eger value of the
desired code point. For example, as Cloudflare has chosen `0xfe30` as the code
point for their hybrid X25519_kyber512 implementation, the following command
can be used to successfully confirm interoperability between the lwocrypt-provider
and the Cloudflare infrastructure using this hybrid classic/quantum-safe algorithm:

```
LWOCRYPT_CODEPOINT_X25519_KYBER512=65072  ./openssl/apps/openssl s_client -groups x25519_kyber512 -connect cloudflare.com:443 -provider-path _build/lwocryptprov -provider lwocryptprovider -provider default
```

# OIDs

Along the same lines as the code points, X.509 OIDs may be subject to change
prior to final standardization. The environment variables below permit
adapting the OIDs of all supported signature algorithms as per the table below.

<!--- LWOCRYPT_TEMPLATE_FRAGMENT_OIDS_START -->
|Algorithm name |    default OID    | enabled | environment variable |
|---------------|:-----------------:|:-------:|----------------------|
| dilithium2 | 1.3.6.1.4.1.2.267.7.4.4 |Yes| LWOCRYPT_OID_DILITHIUM2
| p256_dilithium2 | 1.3.9999.2.7.1 |Yes| LWOCRYPT_OID_P256_DILITHIUM2
| rsa3072_dilithium2 | 1.3.9999.2.7.2 |Yes| LWOCRYPT_OID_RSA3072_DILITHIUM2
| dilithium3 | 1.3.6.1.4.1.2.267.7.6.5 |Yes| LWOCRYPT_OID_DILITHIUM3
| p384_dilithium3 | 1.3.9999.2.7.3 |Yes| LWOCRYPT_OID_P384_DILITHIUM3
| dilithium5 | 1.3.6.1.4.1.2.267.7.8.7 |Yes| LWOCRYPT_OID_DILITHIUM5
| p521_dilithium5 | 1.3.9999.2.7.4 |Yes| LWOCRYPT_OID_P521_DILITHIUM5
| falcon512 | 1.3.9999.3.6 |Yes| LWOCRYPT_OID_FALCON512
| p256_falcon512 | 1.3.9999.3.7 |Yes| LWOCRYPT_OID_P256_FALCON512
| rsa3072_falcon512 | 1.3.9999.3.8 |Yes| LWOCRYPT_OID_RSA3072_FALCON512
| falcon1024 | 1.3.9999.3.9 |Yes| LWOCRYPT_OID_FALCON1024
| p521_falcon1024 | 1.3.9999.3.10 |Yes| LWOCRYPT_OID_P521_FALCON1024
| sphincssha2128fsimple | 1.3.9999.6.4.13 |Yes| LWOCRYPT_OID_SPHINCSSHA2128FSIMPLE
| p256_sphincssha2128fsimple | 1.3.9999.6.4.14 |Yes| LWOCRYPT_OID_P256_SPHINCSSHA2128FSIMPLE
| rsa3072_sphincssha2128fsimple | 1.3.9999.6.4.15 |Yes| LWOCRYPT_OID_RSA3072_SPHINCSSHA2128FSIMPLE
| sphincssha2128ssimple | 1.3.9999.6.4.16 |Yes| LWOCRYPT_OID_SPHINCSSHA2128SSIMPLE
| p256_sphincssha2128ssimple | 1.3.9999.6.4.17 |Yes| LWOCRYPT_OID_P256_SPHINCSSHA2128SSIMPLE
| rsa3072_sphincssha2128ssimple | 1.3.9999.6.4.18 |Yes| LWOCRYPT_OID_RSA3072_SPHINCSSHA2128SSIMPLE
| sphincssha2192fsimple | 1.3.9999.6.5.10 |Yes| LWOCRYPT_OID_SPHINCSSHA2192FSIMPLE
| p384_sphincssha2192fsimple | 1.3.9999.6.5.11 |Yes| LWOCRYPT_OID_P384_SPHINCSSHA2192FSIMPLE
| sphincssha2192ssimple | 1.3.9999.6.5.12 |No| LWOCRYPT_OID_SPHINCSSHA2192SSIMPLE
| p384_sphincssha2192ssimple | 1.3.9999.6.5.13 |No| LWOCRYPT_OID_P384_SPHINCSSHA2192SSIMPLE
| sphincssha2256fsimple | 1.3.9999.6.6.10 |No| LWOCRYPT_OID_SPHINCSSHA2256FSIMPLE
| p521_sphincssha2256fsimple | 1.3.9999.6.6.11 |No| LWOCRYPT_OID_P521_SPHINCSSHA2256FSIMPLE
| sphincssha2256ssimple | 1.3.9999.6.6.12 |No| LWOCRYPT_OID_SPHINCSSHA2256SSIMPLE
| p521_sphincssha2256ssimple | 1.3.9999.6.6.13 |No| LWOCRYPT_OID_P521_SPHINCSSHA2256SSIMPLE
| sphincsshake128fsimple | 1.3.9999.6.7.13 |Yes| LWOCRYPT_OID_SPHINCSSHAKE128FSIMPLE
| p256_sphincsshake128fsimple | 1.3.9999.6.7.14 |Yes| LWOCRYPT_OID_P256_SPHINCSSHAKE128FSIMPLE
| rsa3072_sphincsshake128fsimple | 1.3.9999.6.7.15 |Yes| LWOCRYPT_OID_RSA3072_SPHINCSSHAKE128FSIMPLE
| sphincsshake128ssimple | 1.3.9999.6.7.16 |No| LWOCRYPT_OID_SPHINCSSHAKE128SSIMPLE
| p256_sphincsshake128ssimple | 1.3.9999.6.7.17 |No| LWOCRYPT_OID_P256_SPHINCSSHAKE128SSIMPLE
| rsa3072_sphincsshake128ssimple | 1.3.9999.6.7.18 |No| LWOCRYPT_OID_RSA3072_SPHINCSSHAKE128SSIMPLE
| sphincsshake192fsimple | 1.3.9999.6.8.10 |No| LWOCRYPT_OID_SPHINCSSHAKE192FSIMPLE
| p384_sphincsshake192fsimple | 1.3.9999.6.8.11 |No| LWOCRYPT_OID_P384_SPHINCSSHAKE192FSIMPLE
| sphincsshake192ssimple | 1.3.9999.6.8.12 |No| LWOCRYPT_OID_SPHINCSSHAKE192SSIMPLE
| p384_sphincsshake192ssimple | 1.3.9999.6.8.13 |No| LWOCRYPT_OID_P384_SPHINCSSHAKE192SSIMPLE
| sphincsshake256fsimple | 1.3.9999.6.9.10 |No| LWOCRYPT_OID_SPHINCSSHAKE256FSIMPLE
| p521_sphincsshake256fsimple | 1.3.9999.6.9.11 |No| LWOCRYPT_OID_P521_SPHINCSSHAKE256FSIMPLE
| sphincsshake256ssimple | 1.3.9999.6.9.12 |No| LWOCRYPT_OID_SPHINCSSHAKE256SSIMPLE
| p521_sphincsshake256ssimple | 1.3.9999.6.9.13 |No| LWOCRYPT_OID_P521_SPHINCSSHAKE256SSIMPLE
<!--- LWOCRYPT_TEMPLATE_FRAGMENT_OIDS_END -->

# Key Encodings

By setting environment variables, lwocrypt-provider can be configured to encode keys (subjectPublicKey and and privateKey ASN.1 structures) according to the following IETF drafts:

- https://datatracker.ietf.org/doc/draft-uni-qsckeys-dilithium/00/
- https://datatracker.ietf.org/doc/draft-uni-qsckeys-falcon/00/
- https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/

<!--- LWOCRYPT_TEMPLATE_FRAGMENT_ENCODINGS_START -->
|Environment Variable | Permissible Values |
| --- | --- |
|`LWOCRYPT_ENCODING_DILITHIUM2`|`draft-uni-qsckeys-dilithium-00/sk-pk`|
|`LWOCRYPT_ENCODING_DILITHIUM3`|`draft-uni-qsckeys-dilithium-00/sk-pk`|
|`LWOCRYPT_ENCODING_DILITHIUM5`|`draft-uni-qsckeys-dilithium-00/sk-pk`|
|`LWOCRYPT_ENCODING_FALCON512`|`draft-uni-qsckeys-falcon-00/sk-pk`|
|`LWOCRYPT_ENCODING_FALCON1024`|`draft-uni-qsckeys-falcon-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2128FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2128SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2192FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2192SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2256FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHA2256SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE128FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE128SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE192FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE192SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE256FSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
|`LWOCRYPT_ENCODING_SPHINCSSHAKE256SSIMPLE`|`draft-uni-qsckeys-sphincsplus-00/sk-pk`|
<!--- LWOCRYPT_TEMPLATE_FRAGMENT_ENCODINGS_END -->

By setting `LWOCRYPT_ENCODING_<ALGORITHM>_ALGNAME` environment variables, the corresponding algorithm names are set. The names are documented in the [`qsc_encoding.h`](https://github.com/Quantum-Safe-Collaboration/qsc-key-encoder/blob/main/include/qsc_encoding.h) header file of the encoder library.

If no environment variable is set, or if an unknown value is set, the default is 'no' encoding, meaning that key serialization uses the 'raw' keys of the crypto implementations. If unknown values are set as environment variables, a run-time error will be raised.

The test script `scripts/runtests_encodings.sh` (instead of `scripts/runtests.sh`) can be used for a test run with all supported encodings activated.
