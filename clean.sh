#!/bin/bash

pushd `dirname $0` &> /dev/null
WORKDIR=`pwd`
popd &> /dev/null

rm -fr $WORKDIR/nss_pbkdf2/*.so $WORKDIR/target
cd $WORKDIR/fips-compliant-vault/
mvn clean
