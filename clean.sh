#!/bin/bash

pushd `dirname $0` 2>&1 > /dev/null
WORKDIR=`pwd`
popd 2>&1 > /dev/null

rm -fr $WORKDIR/nss_pbkdf2/*.so $WORKDIR/target
cd $WORKDIR/fips-compliant-vault/
mvn clean
