#!/bin/bash

#
# This script creates a basic fips compliant vault store to hold masked
# passwords.  There should only be one cert in the store but instead of
# the randomly generated cert here, you should modify this to import your
# own cert using certutil.  Make sure that you have both the public and
# private key when importing your own cert.
#
# The vault store is created in the same directory as this script.
#

pushd `dirname $0` 2>&1 > /dev/null
DBDIR=`pwd`/fips-vault

rm -fr ${DBDIR}
mkdir ${DBDIR}

echo
echo "******************************************"
echo "Create the NSS db for the fips-vault"
echo "******************************************"
modutil -force -create -dbdir ${DBDIR}
chmod a+r ${DBDIR}/*.db

echo
echo "******************************************"
echo "Set fips mode for NSS db"
echo "******************************************"
modutil -force -fips true -dbdir ${DBDIR}

echo
echo "******************************************"
echo "Change the NSS db PIN"
echo "******************************************"
echo "use admin1jboss$ as the nss DB password"
modutil -force -changepw "NSS FIPS 140-2 Certificate DB" -dbdir ${DBDIR}

echo
echo "******************************************"
echo "Add certificate with pub/priv key pair to"
echo "mask the admin key that in turn masks the"
echo "the vaulted passwords."
echo "******************************************"
certutil -S -k rsa -g 2048 -n vaultcert -t "u,u,u" -v 240 -x -s "CN=localhost, OU=MYOU, O=MYORG, L=MYCITY, ST=MYSTATE, C=US" -d ${DBDIR}

popd 2>&1 > /dev/null
