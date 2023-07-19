#!/bin/sh

rv=0

provider2openssl() {
    echo
    echo "Testing lwocryptprovider->lwocrypt-openssl interop for $1:"
    $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-certgen.sh $1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-cmssign.sh $1 sha3-384 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocrypt-openssl-certverify.sh $1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocrypt-openssl-cmsverify.sh $1
}

openssl2provider() {
    echo
    echo "Testing lwocrypt-openssl->lwocryptprovider interop for $1:"
    $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocrypt-openssl-certgen.sh $1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocrypt-openssl-cmssign.sh $1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-certverify.sh $1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-cmsverify.sh $1
}

localalgtest() {
    $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-certgen.sh $1 >> interop.log 2>&1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-certverify.sh $1 >> interop.log 2>&1 && $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-cmssign.sh $1 >> interop.log 2>&1 &&  $LWOCRYPT_PROVIDER_TESTSCRIPTS/lwocryptprovider-ca.sh $1 >> interop.log 2>&1
    if [ $? -ne 0 ]; then
        echo "localalgtest $1 failed. Exiting.".
        cat interop.log
        exit 1
    fi
}

interop() {
    echo ".\c"
    # check if we want to run this algorithm:
    if [ ! -z "$LWOCRYPT_SKIP_TESTS" ]; then
        GREPTEST=$(echo $LWOCRYPT_SKIP_TESTS | sed "s/\,/\\\|/g")
        if echo $1 | grep -q "$GREPTEST"; then
            echo "Not testing $1" >> interop.log
            return
        fi
    fi

    # Check whether algorithm is supported at all:
    $OPENSSL_APP list -signature-algorithms | grep $1 > /dev/null 2>&1
    if [ $? -ne 1 ]; then
	if [ -z "$LOCALTESTONLY" ]; then
            provider2openssl $1 >> interop.log 2>&1 && openssl2provider $1 >> interop.log 2>&1
	else
            localalgtest $1
        fi
    else
        echo "Algorithm $1 not enabled. Exit testing."
        exit 1
    fi

    if [ $? -ne 0 ]; then
        echo "Test for $1 failed. Terminating testing."
        cat interop.log
        exit 1
    fi
}

if [ -z "$LWOCRYPT_PROVIDER_TESTSCRIPTS" ]; then
    export LWOCRYPT_PROVIDER_TESTSCRIPTS=$(pwd)/scripts
fi

if [ ! -z "$OPENSSL_INSTALL" ]; then
    # trying to set config variables suitably for pre-existing OpenSSL installation
    if [ -f $OPENSSL_INSTALL/bin/openssl ]; then
        export OPENSSL_APP=$OPENSSL_INSTALL/bin/openssl
    fi
    if [ -z "$LD_LIBRARY_PATH" ]; then
        if [ -d $OPENSSL_INSTALL/lib64 ]; then
            export LD_LIBRARY_PATH=$OPENSSL_INSTALL/lib64
        elif [ -d $OPENSSL_INSTALL/lib ]; then
            export LD_LIBRARY_PATH=$OPENSSL_INSTALL/lib
        fi
    fi
    if [ -f $OPENSSL_INSTALL/ssl/openssl.cnf ]; then
        export OPENSSL_CONF=$OPENSSL_INSTALL/ssl/openssl.cnf
    fi
fi

if [ -z "$OPENSSL_CONF" ]; then
    export OPENSSL_CONF=$(pwd)/scripts/openssl-ca.cnf
fi

if [ -z "$OPENSSL_APP" ]; then
    if [ -f $(pwd)/openssl/apps/openssl ]; then
        export OPENSSL_APP=$(pwd)/openssl/apps/openssl
    else # if no local openssl src directory is found, rely on PATH...
        export OPENSSL_APP=openssl
    fi
fi

if [ -z "$OPENSSL_MODULES" ]; then
    export OPENSSL_MODULES=$(pwd)/_build/lib
fi

if [ -z "$LD_LIBRARY_PATH" ]; then
    if [ -d $(pwd)/.local/lib64 ]; then
        export LD_LIBRARY_PATH=$(pwd)/.local/lib64
    else
        if [ -d $(pwd)/.local/lib ]; then
            export LD_LIBRARY_PATH=$(pwd)/.local/lib
        fi
    fi
fi

if [ ! -z "$LWOCRYPT_SKIP_TESTS" ]; then
   echo "Skipping algs $LWOCRYPT_SKIP_TESTS"
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

echo "Test setup:"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "OPENSSL_APP=$OPENSSL_APP"
echo "OPENSSL_CONF=$OPENSSL_CONF"
echo "OPENSSL_MODULES=$OPENSSL_MODULES"
if [[ "$OSTYPE" == "darwin"* ]]; then
echo "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH"
fi

# check if we can use docker or not:
docker info 2>&1 | grep Server > /dev/null
if [ $? -ne 0 ]; then
   echo "No LWOCRYPT-OpenSSL111 interop test because of absence of docker"
   export LOCALTESTONLY="Yes"
fi

# by default, do not run interop tests as per 
# https://github.com/vld375/lwocrypt-provider/issues/32
# comment the following line if they should be run; be sure to
# have alignment in algorithms supported in that case
export LOCALTESTONLY="Yes"

echo "Version information:"
$OPENSSL_APP version

# Disable testing for version 3.0.1: Buggy as hell:
$OPENSSL_APP version | grep "OpenSSL 3.0.1" > /dev/null
if [ $? -eq 0 ]; then
   echo "Skipping testing of buggy OpenSSL 3.0.1"
   exit 0
fi

$OPENSSL_APP list -providers -verbose
if [ $? -ne 0 ]; then
   echo "Baseline openssl invocation failed. Exiting test."
   exit 1
fi

# Ensure "lwocryptprovider" is registered:
$OPENSSL_APP list -providers -verbose | grep lwocryptprovider > /dev/null
if [ $? -ne 0 ]; then
   echo "lwocryptprovider not registered. Exit test."
   exit 1
fi

# Run interop-tests:
# cleanup log from previous runs:
rm -f interop.log

echo "Cert gen/verify, CMS sign/verify, CA tests for all enabled LWOCRYPT signature algorithms commencing: "

# auto-detect all available signature algorithms:
for alg in `$OPENSSL_APP list -signature-algorithms | grep lwocryptprovider | sed -e "s/ @ .*//g" | sed -e "s/^  //g"`
do 
   if [ "$1" = "-V" ]; then
      echo "Testing $alg"
   fi
   interop $alg
   certsgenerated=1
done

if [ -z $certsgenerated ]; then
   echo "No LWOCRYPT signature algorithms found in provider 'lwocryptprovider'. No certs generated. Exiting."
   exit 1
else
   if [ "$1" = "-V" ]; then
      echo "Certificates successfully generated in $(pwd)/tmp"
   fi
fi

echo

# Run built-in tests:
# Without removing OPENSSL_CONF ctest hangs... ???
unset OPENSSL_CONF
cd _build && ctest $@ && cd ..

if [ $? -ne 0 ]; then
   rv=1
fi

# cleanup: TBC:
# decide for testing strategy when integrating to OpenSSL test harness:
# Keep scripts generating certs (testing more code paths) or use API?
#rm -rf tmp
echo

if [ $rv -ne 0 ]; then
   echo "Tests failed."
else
   echo "All lwocryptprovider tests passed."
fi
exit $rv

