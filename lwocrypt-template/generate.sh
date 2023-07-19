#!/bin/bash

cd lwocrypt-template 

rm generate.yml

# Step 1: Obtain current generate.yml from main:
wget -c https://raw.githubusercontent.com/vld375/openssl/LWOCRYPT-OpenSSL_1_1_1-stable/lwocrypt-template/generate.yml

# Step 2: Run the generator:
cd .. && python3 lwocrypt-template/generate.py 
