#!/bin/bash

# Use dockerimage to generate certs for alg $1

IMAGE=openquantumsafe/curl

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

#rm -rf tmp
mkdir -p tmp

if [[ -z "$CIRCLECI" ]]; then
docker run -v `pwd`/tmp:/home/lwocrypt/data -it $IMAGE sh -c "cd /home/lwocrypt/data && openssl req -x509 -new -newkey $1 -keyout $1_CA.key -out $1_CA.crt -nodes -subj \"/CN=lwocrypttest CA\" -days 365 -config /opt/lwocryptsa/ssl/openssl.cnf && openssl genpkey -algorithm $1 -out $1_srv.key && openssl req -new -newkey $1 -keyout $1_srv.key -out $1_srv.csr -nodes -subj \"/CN=lwocrypttest server\" -config /opt/lwocryptsa/ssl/openssl.cnf && openssl x509 -req -in $1_srv.csr -out $1_srv.crt -CA $1_CA.crt -CAkey $1_CA.key -CAcreateserial -days 365 && openssl verify -CAfile $1_CA.crt $1_srv.crt"
else
# CCI doesn't permit mounting, so let's do as per https://circleci.com/docs/2.0/building-docker-images/#mounting-folders:
docker run --name lwocryptossl -it $IMAGE sh -c "mkdir /home/lwocrypt/tmp && cd /home/lwocrypt/tmp && openssl req -x509 -new -newkey $1 -keyout $1_CA.key -out $1_CA.crt -nodes -subj \"/CN=lwocrypttest CA\" -days 365 -config /opt/lwocryptsa/ssl/openssl.cnf && openssl genpkey -algorithm $1 -out $1_srv.key && openssl req -new -newkey $1 -keyout $1_srv.key -out $1_srv.csr -nodes -subj \"/CN=lwocrypttest server\" -config /opt/lwocryptsa/ssl/openssl.cnf && openssl x509 -req -in $1_srv.csr -out $1_srv.crt -CA $1_CA.crt -CAkey $1_CA.key -CAcreateserial -days 365 && openssl verify -CAfile $1_CA.crt $1_srv.crt"
docker cp lwocryptossl:/home/lwocrypt/tmp .
docker rm lwocryptossl
fi

