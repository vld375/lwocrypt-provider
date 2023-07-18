#!/bin/bash

# The following variables influence the operation of this build script:
# Argument -f: Soft clean, ensuring re-build of lwocrypt-provider binary
# Argument -F: Hard clean, ensuring checkout and build of all dependencies
# EnvVar MAKE_PARAMS: passed to invocations of make; sample value: "-j"
# EnvVar LIBLWOCRYPT_BRANCH: Defines branch/release of liblwocrypt; default value "main"
# EnvVar LWOCRYPT_ALGS_ENABLED: If set, defines LWOCRYPT algs to be enabled, e.g., "STD"
# EnvVar OPENSSL_INSTALL: If set, defines (binary) OpenSSL installation to use
# EnvVar OPENSSL_BRANCH: Defines branch/release of openssl; if set, forces source-build of OpenSSL3
# EnvVar liblwocrypt_DIR: If set, needs to point to a directory where liblwocrypt has been installed to

if [[ "$OSTYPE" == "darwin"* ]]; then
   SHLIBEXT="dylib"
   STATLIBEXT="dylib"
else
   SHLIBEXT="so"
   STATLIBEXT="a"
fi

if [ $# -gt 0 ]; then
   if [ "$1" == "-f" ]; then
      rm -rf _build
   fi
   if [ "$1" == "-F" ]; then
      rm -rf _build openssl liblwocrypt .local
   fi
fi

if [ -z "$LIBLWOCRYPT_BRANCH" ]; then
   export LIBLWOCRYPT_BRANCH=main
fi

if [ -z "$LWOCRYPT_ALGS_ENABLED" ]; then
   export DLWOCRYPT_ALGS_ENABLED=""
else
   export DLWOCRYPT_ALGS_ENABLED="$LWOCRYPT_ALGS_ENABLED"
fi

if [ -z "$OPENSSL_INSTALL" ]; then
 openssl version | grep "OpenSSL 3" > /dev/null 2>&1
 #if [ \($? -ne 0 \) -o \( ! -z "$OPENSSL_BRANCH" \) ]; then
 if [ $? -ne 0 ] || [ ! -z "$OPENSSL_BRANCH" ]; then
   if [ -z "$OPENSSL_BRANCH" ]; then
      export OPENSSL_BRANCH="master"
   fi
   # No OSSL3 installation given/found, or specific branch build requested
   echo "OpenSSL3 to be built from source at branch $OPENSSL_BRANCH."

   if [ ! -d "openssl" ]; then
      echo "openssl not specified and doesn't reside where expected: Cloning and building..."
      # for full debug build add: enable-trace enable-fips --debug
      export OSSL_PREFIX=`pwd`/.local && git clone --depth 1 --branch $OPENSSL_BRANCH git://git.openssl.org/openssl.git && cd openssl && LDFLAGS="-Wl,-rpath -Wl,${OSSL_PREFIX}/lib64" ./config --prefix=$OSSL_PREFIX && make $MAKE_PARAMS && make install_sw install_ssldirs && cd ..
      if [ $? -ne 0 ]; then
        echo "openssl build failed. Exiting."
        exit -1
      fi
   fi
 fi
fi

# Check whether liblwocrypt is built or has been configured:
if [ -z $liblwocrypt_DIR ]; then
 if [ ! -f ".local/lib/liblwocrypt.$STATLIBEXT" ]; then
  echo "need to re-build static liblwocrypt..."
  if [ ! -d liblwocrypt ]; then
    echo "cloning liblwocrypt $LIBLWOCRYPT_BRANCH..."
    git clone --depth 1 --branch $LIBLWOCRYPT_BRANCH https://github.com/open-quantum-safe/liblwocrypt.git
    if [ $? -ne 0 ]; then
      echo "liblwocrypt clone failure for branch $LIBLWOCRYPT_BRANCH. Exiting."
      exit -1
    fi
    if [ "$LIBLWOCRYPT_BRANCH" != "main" ]; then
      # check for presence of backwards-compatibility generator file
      if [ -f lwocrypt-template/generate.yml-$LIBLWOCRYPT_BRANCH ]; then
        echo "generating code for $LIBLWOCRYPT_BRANCH"
        mv lwocrypt-template/generate.yml lwocrypt-template/generate.yml-main
        cp lwocrypt-template/generate.yml-$LIBLWOCRYPT_BRANCH lwocrypt-template/generate.yml
        LIBLWOCRYPT_SRC_DIR=`pwd`/liblwocrypt python3 lwocrypt-template/generate.py
        if [ $? -ne 0 ]; then
           echo "Code generation failure for $LIBLWOCRYPT_BRANCH. Exiting."
           exit -1
        fi
      fi
    fi
  fi

  # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
  # to optimize for size add -DLWOCRYPT_ALGS_ENABLED= suitably to one of these values:
  #    STD: only include NIST standardized algorithms
  #    NIST_R4: only include algorithms in round 4 of the NIST competition
  #    All: include all algorithms supported by liblwocrypt (default)
  cd liblwocrypt && cmake -GNinja $DLWOCRYPT_ALGS_ENABLED -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build && cd _build && ninja && ninja install && cd ../..
  if [ $? -ne 0 ]; then
      echo "liblwocrypt build failed. Exiting."
      exit -1
  fi
 fi
 export liblwocrypt_DIR=$(pwd)/.local
fi

# Check whether provider is built:
if [ ! -f "_build/lib/lwocryptprovider.$SHLIBEXT" ]; then
   echo "lwocryptprovider (_build/lib/lwocryptprovider.$SHLIBEXT) not built: Building..."
   # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
   #BUILD_TYPE="-DCMAKE_BUILD_TYPE=Debug"
   BUILD_TYPE=""
   # for omitting public key in private keys add -DNOPUBKEY_IN_PRIVKEY=ON
   if [ -z "$OPENSSL_INSTALL" ]; then
       cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local $BUILD_TYPE -S . -B _build && cmake --build _build
   else
       cmake -DOPENSSL_ROOT_DIR=$OPENSSL_INSTALL $BUILD_TYPE -S . -B _build && cmake --build _build
   fi
   if [ $? -ne 0 ]; then
     echo "provider build failed. Exiting."
     exit -1
   fi
fi

