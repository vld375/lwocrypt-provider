[![GitHub actions](https://github.com/vld375/lwocrypt-provider/actions/workflows/linux.yml/badge.svg)](https://github.com/vld375/lwocrypt-provider/actions/workflows/linux.yml)
[![GitHub actions](https://github.com/vld375/lwocrypt-provider/actions/workflows/windows.yml/badge.svg)](https://github.com/vld375/lwocrypt-provider/actions/workflows/windows.yml)
[![lwocrypt-provider](https://circleci.com/gh/vld375/lwocrypt-provider.svg?style=svg)](https://app.circleci.com/pipelines/github/vld375/lwocrypt-provider)

lwocryptprovider - Open Quantum Safe provider for OpenSSL (3.x)
==========================================================

Purpose
-------

This repository contains code to enable quantum-safe cryptography (QSC)
in a standard OpenSSL (3.x) distribution by way of implementing a single
shared library, the LWOCRYPT
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html).

This repository has been derived from the [LWOCRYPT-OpenSSL3 branch in
https://github.com/vld375/openssl](https://github.com/vld375/openssl/tree/LWOCRYPT-OpenSSL3)
creating a provider that can be built outside the OpenSSL source tree.

Status
------

Currently this provider fully enables quantum-safe cryptography for KEM
key establishment in TLS1.3 including management of such keys via the
OpenSSL (3.0) provider interface and hybrid KEM schemes. Also, QSC
signatures including CMS and CMP functionality are available via the OpenSSL
EVP interface. Key persistence is provided via the encode/decode
mechanism and X.509 data structures. Also available is support for 
TLS1.3 signature functionality via the [OpenSSL3 fetchable signature
algorithm feature](https://github.com/openssl/openssl/pull/19312).

Standards implemented
---------------------

For non-post-quantum algorithms, this provider is basically silent, i.e.,
permits use of standards and algorithms implemented by [openssl](https://github.com/openssl/openssl)
, e.g., concerning X.509, PKCS#8 or CMS.

For post-quantum algorithms, the version of the cryptographic algorithm used
depends on the version of [liblwocrypt](https://github.com/vld375/liblwocrypt) used.
Regarding the integration of post-quantum algorithms into higher level
components, this provider implements the following standards:

- For TLS:
  - Hybrid post-quantum / traditional key exchange:
    - The data structures used follow the Internet-Draft [Hybrid key exchange in TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/), namely simple concatenation of traditional and post-quantum public keys and shared secrets.
    - The algorithm identifiers used are documented in [lwocrypt-kem-info.md](https://github.com/vld375/lwocrypt-provider/blob/main/lwocrypt-template/lwocrypt-kem-info.md).
  - Hybrid post-quantum / traditional signatures in TLS:
    - For public keys and digital signatures inside X.509 certificates, see the bullet point on X.509 below.
    - For digital signatures outside X.509 certificates and in the TLS 1.3 handshake directly, the data structures used follow the same encoding format as that used for X.509 certificates, namely simple concatenation of traditional and post-quantum signatures.
    - The algorithm identifiers used are documented in [lwocrypt-sig-info.md](https://github.com/vld375/lwocrypt-provider/blob/main/lwocrypt-template/lwocrypt-sig-info.md).
- For X.509:
  - Hybrid post-quantum / traditional public keys and signatures:
    - The data structures used follow the Internet-Draft [Internet X.509 Public Key Infrastructure: Algorithm Identifiers for Dilithium](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/), namely simple concatenation of traditional and post-quantum components in plain binary / OCTET_STRING representations.
    - The algorithm identifiers (OIDs) used are documented in [lwocrypt-sig-info.md](https://github.com/vld375/lwocrypt-provider/blob/main/lwocrypt-template/lwocrypt-sig-info.md).
- For PKCS#8:
  - Hybrid post-quantum / traditional private keys:
    - Simple concatenation of traditional and post-quantum components in plain binary / OCTET_STRING representations.

Additionally worthwhile noting is that only quantum-safe [signature algorithms](#signature-algorithms) are persisted via PKCS#8 and X.509. No corresponding encoder/decoder logic exists for quantum safe [KEM algorithms](#kem-algorithms) -- See also #194.

Algorithms
----------

This implementation makes available the following quantum safe algorithms:

<!--- LWOCRYPT_TEMPLATE_FRAGMENT_ALGS_START -->
### KEM algorithms

- **BIKE**: `bikel1`, `p256_bikel1`, `x25519_bikel1`, `bikel3`, `p384_bikel3`, `x448_bikel3`, `bikel5`, `p521_bikel5`
- **CRYSTALS-Kyber**: `kyber512`, `p256_kyber512`, `x25519_kyber512`, `kyber768`, `p384_kyber768`, `x448_kyber768`, `x25519_kyber768`, `p256_kyber768`, `kyber1024`, `p521_kyber1024`
- **FrodoKEM**: `frodo640aes`, `p256_frodo640aes`, `x25519_frodo640aes`, `frodo640shake`, `p256_frodo640shake`, `x25519_frodo640shake`, `frodo976aes`, `p384_frodo976aes`, `x448_frodo976aes`, `frodo976shake`, `p384_frodo976shake`, `x448_frodo976shake`, `frodo1344aes`, `p521_frodo1344aes`, `frodo1344shake`, `p521_frodo1344shake`
- **HQC**: `hqc128`, `p256_hqc128`, `x25519_hqc128`, `hqc192`, `p384_hqc192`, `x448_hqc192`, `hqc256`, `p521_hqc256`†

### Signature algorithms

- **CRYSTALS-Dilithium**:`dilithium2`\*, `p256_dilithium2`\*, `rsa3072_dilithium2`\*, `dilithium3`\*, `p384_dilithium3`\*, `dilithium5`\*, `p521_dilithium5`\*
- **Falcon**:`falcon512`\*, `p256_falcon512`\*, `rsa3072_falcon512`\*, `falcon1024`\*, `p521_falcon1024`\*

- **SPHINCS-SHA2**:`sphincssha2128fsimple`\*, `p256_sphincssha2128fsimple`\*, `rsa3072_sphincssha2128fsimple`\*, `sphincssha2128ssimple`\*, `p256_sphincssha2128ssimple`\*, `rsa3072_sphincssha2128ssimple`\*, `sphincssha2192fsimple`\*, `p384_sphincssha2192fsimple`\*, `sphincssha2192ssimple`, `p384_sphincssha2192ssimple`, `sphincssha2256fsimple`, `p521_sphincssha2256fsimple`, `sphincssha2256ssimple`, `p521_sphincssha2256ssimple`
- **SPHINCS-SHAKE**:`sphincsshake128fsimple`\*, `p256_sphincsshake128fsimple`\*, `rsa3072_sphincsshake128fsimple`\*, `sphincsshake128ssimple`, `p256_sphincsshake128ssimple`, `rsa3072_sphincsshake128ssimple`, `sphincsshake192fsimple`, `p384_sphincsshake192fsimple`, `sphincsshake192ssimple`, `p384_sphincsshake192ssimple`, `sphincsshake256fsimple`, `p521_sphincsshake256fsimple`, `sphincsshake256ssimple`, `p521_sphincsshake256ssimple`

<!--- LWOCRYPT_TEMPLATE_FRAGMENT_ALGS_END -->

As the underlying [liblwocrypt](https://github.com/vld375/liblwocrypt)
at build time may be configured to not enable all algorithms, it is
advisable to check the possible subset of algorithms actually enabled
via the standard commands, i.e.,
`openssl list -signature-algorithms -provider lwocryptprovider` and
`openssl list -kem-algorithms -provider lwocryptprovider`.

In addition, algorithms not denoted with "\*" above are not enabled for
TLS operations. This designation can be changed by modifying the
"enabled" flags in the main [algorithm configuration file](lwocrypt-template/generate.yml)
and re-running the generator script `python3 lwocrypt-template/generate.py`.

It is possible to select only algorithms of a specific bit strength by using
the openssl property selection mechanism on the key "lwocryptprovider.security_bits",
e.g., as such: `openssl list -kem-algorithms -propquery lwocryptprovider.security_bits=256`.
The bit strength of hybrid algorithms is always defined by the bit strength
of the classic algorithm.

In order to enable parallel use of classic and quantum-safe cryptography 
this provider also provides different hybrid algorithms, combining classic
and quantum-safe methods: These are listed above with a prefix denoting a
classic algorithm, e.g., for elliptic curve: "p256_".

A full list of algorithms, their interoperability code points and OIDs as well
as a method to dynamically adapt them are documented in [ALGORITHMS.md](ALGORITHMS.md).

*Note:* `lwocryptprovider` depends for TLS session setup and hybrid operations
on OpenSSL providers for classic crypto operations. Therefore it is essential
that a provider such as `default` or `fips` is configured to be active. See
`tests/lwocrypt.cnf` or `scripts/openssl-ca.cnf` for examples.

Building and testing -- Quick start
-----------------------------------

All component builds and testing described in detail below can be executed by
running the scripts `scripts/fullbuild.sh` and `scripts/runtests.sh`
respectively (tested on Linux Ubuntu and Mint as well as OSX).

By default, these scripts always build and test against the current OpenSSL `master` branch.

These scripts can be configured by setting various environment variables as documented in the scripts.
For information the following environment settings may be of most interest:

- OPENSSL_INSTALL: Directory of an existing, non-standard OpenSSL binary distribution
- OPENSSL_BRANCH: Tag of a specific OpenSSL release to be built and used in testing


Building and testing
--------------------

## Pre-requisites

To be able to build `lwocryptprovider`, OpenSSL 3.0 and liblwocrypt need to be installed.
It's not important where they are installed, just that they are.

For building, minimum requirements are a C compiler, git access and `cmake`.
For Linux these commands can typically be installed by running for example

    sudo apt install build-essential git cmake

### OpenSSL 3

If OpenSSL3 is not already installed, the following shows an example for building
and installing the latest/`master` branch of OpenSSL 3 in `.local`:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw
    cd ..

For [OpenSSL implementation limitations, e.g., regarding provider feature usage and support,
see here](https://wiki.openssl.org/index.php/OpenSSL_3.0#STATUS_of_current_development).

### liblwocrypt

Example for building and installing liblwocrypt in `.local`:

    git clone https://github.com/vld375/liblwocrypt.git
    cd liblwocrypt
    cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build
    cmake --build _build && cmake --install _build
    cd ..

Further `liblwocrypt` build options are [documented here](https://github.com/vld375/liblwocrypt/wiki/Customizing-liblwocrypt).

## Building the provider (UNIX - Linux - OSX)

`lwocryptprovider` using the local OpenSSL3 build as done above can be built for example via the following:

    cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local -DCMAKE_PREFIX_PATH=$(pwd)/.local -S . -B _build
    cmake --build _build

## Testing

Core component testing can be run via the common `cmake` command:

    ctest --parallel 5 --test-dir _build --rerun-failed --output-on-failure

Add `-V` to the `ctest` command for verbose output.

Additional interoperability tests (with LWOCRYPT-OpenSSL1.1.1) are available in the
script `scripts/runtests.sh` but are disabled by default as lwocrypt-openssl111 has
a smaller set of algorithms and features supported.

## Packaging

A build target to create .deb packaging is available via the standard `package`
target, e.g., executing `make package` in the `_build` subdirectory.
The resultant file can be installed as usual via `dpkg -i ...`.

## Installing the provider

`lwocryptprovider` can be installed using the common `cmake` command

    cmake --install _build

If it is desired to activate `lwocryptprovider` by default in the system `openssl.cnf`
file, amend the "[provider_sect]" as follows:

```
[provider_sect]
default = default_sect
lwocryptprovider = lwocryptprovider_sect
[lwocryptprovider_sect]
activate = 1
```

This file is typically located at (operating system dependent):
- /etc/ssl/openssl.cnf (UNIX/Linux)
- /opt/homebrew/etc/openssl@3/openssl.cnf (OSX Homebrew)
- C:\Program Files\Common Files\SSL\openssl.cnf (Windows)

Doing this will enable `lwocryptprovider` to be seamlessly used alongside the other
`openssl` providers. If successfully done, running, e.g., `openssl list -providers`
should output something along these lines (version IDs variable of course):

```
providers:
  default
    name: OpenSSL Default Provider
    version: 3.1.1
    status: active
  lwocryptprovider
    name: OpenSSL LWOCRYPT Provider
    version: 0.5.0
    status: active
```

If this is the case, all `openssl` commands can be used as usual, extended
by the option to use quantum safe cryptographic algorithms in addition/instead
of classical crypto algorithms.

## Build and test options

### Size optimizations

In order to reduce the size of the lwocryptprovider, it is possible to limit the number
of algorithms supported, e.g., to the set of NIST standardized algorithms. This is
facilitated by setting the `liblwocrypt` build option `-DLWOCRYPT_ALGS_ENABLED=STD`.

Another option to reduce the size of `lwocryptprovider` is to have it rely on a
separate installation of `liblwocrypt` (as a shared library). For such deployment be
sure to specify the standard [BUILD_SHARED_LIBS](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html)
option of `cmake`.

### ninja

By adding the standard CMake option `-GNinja` the ninja build system can be used,
enabling the usual `ninja`, `ninja test`, or `ninja package` commands.

### NDEBUG

By adding the standard CMake option `-DCMAKE_BUILD_TYPE=Release` to the
`lwocryptprovider` build command, debugging output is disabled.

### LWOCRYPT_SKIP_TESTS

By setting this environment variable, testing of specific
algorithm families as listed [here](https://github.com/vld375/openssl#supported-algorithms)
can be disabled in testing. For example

    LWOCRYPT_SKIP_TESTS="sphincs" ./scripts/runtests.sh

excludes all algorithms of the "Sphincs" family (speeding up testing significantly).

*Note*: By default, interoperability testing with lwocrypt-openssl111 is no longer
performed by default but can be manually enabled in the script `scripts/runtests.sh`.

### Key Encoding

By setting `-DUSE_ENCODING_LIB=<ON/OFF>` at compile-time, lwocrypt-provider can be
compiled with with an an external encoding library `qsc-key-encoder`.
Configuring the encodings is done via environment as described in [ALGORITHMS.md](ALGORITHMS.md).
The default value is `OFF`.

By setting `-DNOPUBKEY_IN_PRIVKEY=<ON/OFF>` at compile-time, it can be further
specified to omit explicitly serializing the public key in a `privateKey`
structure. The default value is `OFF`.

Building on Windows
--------------------
Building `lwocryptprovider` following the steps outlined above have been
successfully tested on Windows 10 and 11 using MSYS2 MINGW64.
For building `lwocryptprovider` successfully using Microsoft Visual Studio
or `cygwin`, please check out the build instructions for those platforms
in the CI control file at ".github/workflows/windows.yml".

Using
-----

In order to exercise the `lwocryptprovider`, it needs to be explicitly activated.
One way to do this is to enable it in the OpenSSL config file. Detailed
explanations can be found for example
[here](https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers).

An example file activating `lwocryptprovider` by default is `scripts/openssl-ca.cnf`.
This can be activated for example by setting the standard OpenSSl environment
variable "OPENSSL_CONF" to this file before using `openssl`, e.g. in UNIX notation:

    setenv OPENSSL_CONF=scripts/openssl-ca.cnf

Another alternative is to explicitly request its use on the command line.
The following examples use that option. All examples below assume openssl (3.0)
to be located in a folder `.local` in the local directory as per the
building examples above. Having OpenSSL(3) installed in a standard location
eliminates the need for specific PATH setting as showcased below.

## Checking provider version information

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl list -providers -verbose -provider-path _build/lib -provider lwocryptprovider 

If using a standard install of openssl(3) and including `lwocryptprovider` activation
in the global "openssl.cnf" file, the command accordingly gets simplified to:

    openssl list -providers -verbose

## Creating (classic) keys and certificates

This can be facilitated for example by using the usual `openssl` commands:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey rsa -keyout rsa_CA.key -out rsa_CA.crt -nodes -subj "/CN=test CA" -days 365 -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl genpkey -algorithm rsa -out rsa_srv.key
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -new -newkey rsa -keyout rsa_srv.key -out rsa_srv.csr -nodes -subj "/CN=test server" -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -req -in rsa_srv.csr -out rsa_srv.crt -CA rsa_CA.crt -CAkey rsa_CA.key -CAcreateserial -days 365

These examples create classic RSA keys but the very same commands can be used
to create PQ certificates replacing the key type "rsa" with any of the PQ
signature algorithms [listed above](#signature-algorithms).

## Setting up a (quantum-safe) test server

A simple server utilizing PQ/quantum-safe KEM algorithms and classic RSA
certicates can be set up for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake -provider-path _build/lib  -provider default -provider lwocryptprovider

## Running a client to interact with (quantum-safe) KEM algorithms

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_client -groups frodo640shake -provider-path _build/lib  -provider default -provider lwocryptprovider

By issuing the command `GET /` the quantum-safe crypto enabled OpenSSL3
server returns details about the established connection.

Any [available quantum-safe/PQ KEM algorithm](#kem-algorithms) can be selected by passing it in the `-groups` option.

## S/MIME message signing -- Cryptographic Message Syntax (CMS)

Also possible is the creation and verification of quantum-safe digital
signatures using [CMS](https://datatracker.ietf.org/doc/html/rfc5652).

#### Signing data

For creating signed data, two steps are required: One is the creation
of a certificate using a QSC algorithm; the second is the use of this
certificate (and its signature algorithm) to create the signed data:

Step 1: Create quantum-safe key pair and self-signed certificate:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey dilithium3 -keyout qsc.key -out qsc.crt -nodes -subj "/CN=lwocrypttest" -days 365 -config openssl/apps/openssl.cnf -provider-path _build/lib -provider lwocryptprovider -provider default

By changing the `-newkey` parameter algorithm name [any of the 
supported quantum-safe or hybrid algorithms](#signature-algorithms)
can be utilized instead of the sample algorithm `dilithium3`.

Step 2: Sign data:

As
[the CMS standard](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
requires the presence of a digest algorithm, while quantum-safe crypto
does not, in difference to the QSC certificate creation command above,
passing a message digest algorithm via the `-md` parameter is mandatory.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -in inputfile -sign -signer qsc.crt -inkey qsc.key -nodetach -outform pem -binary -out signedfile -md sha512 -provider-path _build/lib  -provider default -provider lwocryptprovider

Data to be signed is to be contained in the file named `inputfile`. The
resultant CMS output is contained in file `signedfile`. The QSC algorithm
used is the same signature algorithm utilized for signing the certificate
`qsc.crt`.

#### Verifying data

Continuing the example above, the following command verifies the CMS file
`signedfile` and outputs the `outputfile`. Its contents should be identical
to the original data in `inputfile` above.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -verify -CAfile qsc.crt -inform pem -in signedfile -crlfeol -out outputfile -provider-path _build/lib -provider lwocryptprovider -provider default

Note that it is also possible to build proper QSC certificate chains
using the standard OpenSSL calls. For sample code see
[scripts/lwocryptprovider-certgen.sh](scripts/lwocryptprovider-certgen.sh).

### Support of `dgst` (and sign)

Also tested to operate OK is the [openssl dgst](https://www.openssl.org/docs/man3.0/man1/openssl-dgst.html)
command. Sample invocations building on the keys and certificate files in the examples above:

#### Signing

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/lib -provider lwocryptprovider -provider default -sign qsc.key -out dgstsignfile inputfile

#### Verifying

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/lib -provider lwocryptprovider -provider default -signature dgstsignfile -verify qsc.pubkey inputfile

The public key can be extracted from the certificate using standard openssl command:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -provider-path _build/lib -provider lwocryptprovider -provider default -in qsc.crt -pubkey -noout > qsc.pubkey

The `dgst` command is not tested for interoperability with [lwocrypt-openssl111](https://github.com/vld375/openssl).

### Note on randomness provider

`lwocryptprovider` does not implement its own
[DRBG](https://csrc.nist.gov/glossary/term/Deterministic_Random_Bit_Generator).
Therefore by default it relies on OpenSSL to provide one. Thus,
either the default or fips provider must be loaded for QSC algorithms
to have access to OpenSSL-provided randomness. Check out
[OpenSSL provider documentation](https://www.openssl.org/docs/manmaster/man7/provider.html)
and/or [OpenSSL command line options](https://www.openssl.org/docs/manmaster/man1/openssl.html)
on how to facilitate this. Or simply use the sample command
lines documented in this README.

This dependency could be eliminated by building `liblwocrypt` without
OpenSSL support ([LWOCRYPT_USE_OPENSSL=OFF](https://github.com/vld375/liblwocrypt/wiki/Customizing-liblwocrypt#LWOCRYPT_USE_OPENSSL)),
which of course would be an unusual approach for an OpenSSL-LWOCRYPT provider.

### Note on KEM Decapsulation API

The OpenSSL [`EVP_PKEY_decapsulate` API](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decapsulate.html) specifies an explicit return value for failure. For security reasons, most KEM algorithms available from liblwocrypt do not return an error code if decapsulation failed. Successful decapsulation can instead be implicitly verified by comparing the original and the decapsulated message.

Note on OpenSSL versions
------------------------

`lwocryptprovider` is written to ensure building on all versions of OpenSSL
supporting the provider concept. However, OpenSSL still is in active
development regarding features supported via the provider interface.
Therefore some functionalities documented above are only supported
with specific OpenSSL versions:

## 3.0/3.1

In these versions, CMS functionality implemented in providers is not
supported: The resolution of https://github.com/openssl/openssl/issues/17717
has not been not getting back-ported to OpenSSL3.0.

Also not supported in this version are provider-based signature algorithms
used during TLS1.3 operations as documented in https://github.com/openssl/openssl/issues/10512.

## 3.2(-dev)

After https://github.com/openssl/openssl/pull/19312 landed, (also PQ) signature
algorithms are working in TLS1.3 (handshaking); after https://github.com/openssl/openssl/pull/20486
has landed, also algorithms with very long signatures are supported.

liblwocrypt dependency
-----------------

As `lwocryptprovider` is dependent on `liblwocrypt` for the implementation of the PQ algorithms
there is a mechanism to adapt the functionality of a specific `liblwocrypt` version to the
current `lwocryptprovider` version: The use of the code generator script `lwocrypt-template/generate.py`
which in turn is driven by any of the `liblwocrypt` release-specific `lwocrypt-template/generate.yml[-release]`
files. The same file(s) also define the (default) TLS IDs of all algorithms included and
therefore represent the interoperability level at a specific point in time (of development
of `lwocryptprovider` and `liblwocrypt`).

By default, `lwocryptprovider` always uses the most current version of `liblwocrypt` code, but by
setting the environment variable "LIBLWOCRYPT_BRANCH" when running the `scripts/fullbuild.sh`
script, code will be generated to utilize a specific, supported `liblwocrypt` release. The
script `scripts/revertmain.sh` can be used to revert all code back to the default,
`main`-branch tracking strategy. This can be used, for example, to facilitate a release
of `lwocryptprovider` to track an old `liblwocrypt` release.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to the `lwocryptprovider` include:

- Michael Baentsch
- Christian Paquin
- Richard Levitte
- Basil Hess
- Julian Segeth
- Alex Zaslavsky
- Will Childs-Klein

Acknowledgments
---------------

The `lwocryptprovider` project is supported through the [NGI Assure Fund](https://nlnet.nl/assure),
a fund established by [NLnet](https://nlnet.nl) with financial
support from the European Commission's [Next Generation Internet programme](https://www.ngi.eu),
under the aegis of DG Communications Networks, Content and Technology
under grant agreement No 957073.

Financial support for the development of Open Quantum Safe has been provided
by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have
dedicated programmer time to contribute source code to LWOCRYPT, including
Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of LWOCRYPT have been
supported by various research grants, including funding from the Natural
Sciences and Engineering Research Council of Canada (NSERC); see
[here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and
[here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf)
for funding acknowledgments.
