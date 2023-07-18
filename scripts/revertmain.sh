#!/bin/bash

# This script reverts to a possibly set "main" code generator script

if [ -f lwocrypt-template/generate.yml-main ]; then
    rm -rf liblwocrypt && git clone --depth 1 --branch main https://github.com/open-quantum-safe/liblwocrypt.git
    mv lwocrypt-template/generate.yml-main lwocrypt-template/generate.yml
    LIBLWOCRYPT_SRC_DIR=`pwd`/liblwocrypt python3 lwocrypt-template/generate.py
    if [ $? -ne 0 ]; then
       echo "Code generation failure for main branch. Exiting."
       exit -1
    fi
    # remove liblwocrypt.a to ensure rebuild against newly generated code
    rm .local/lib/liblwocrypt.a
    git status
fi

