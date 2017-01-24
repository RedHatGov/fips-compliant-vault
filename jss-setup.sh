#!/bin/bash

# This script creates a FIPS compliant security vault implementation
# packaged as a JBoss EAP 6.x module.  Pre-built artifacts are in the
# dist directory.  The module contains a script to initialize and insert
# entries into the vault, two native libraries, a jar file for the vault
# implementation and the  signed Mozilla Java Security Services (JSS) jar.
#
# The specific files in the module are:
#
#  fips-vault.sh    - script to initialize and populate vault 
#  jss4.jar         - the signed Mozilla JSS library
#  libjss4.so       - JNI method implementation needed by jss4.jar
#  libnss_pbkdf2.so - exposes the Mozilla Network Security Services (NSS)
#                     implementation of PKCS#5 PBKDF2 as a JNI method for
#                     the vault implementation
# 
# The bulk of this script attempts to automate these build instructions
# [1] for NSS and NSPR and these build instructions [2] for JSS.
# These artifacts will be built to closely match what's installed on the
# platform.
#
# NB: The security vault implementation will only use the platform installed
#     binaries for NSS and NSPR when accessing NSS through the Mozilla-JSS JCA
#     provider or the pbkdf2 JNI method.  The local builds of NSS and NSPR are
#     solely for the purpose of building the native shared libraries for the
#     vault implementation.
#
# Any needed dependencies will be downloaded automatically.  If you lack
# network connectivity, this behavior can be bypassed by copying needed
# dependencies to the target directory.
#
# The version of mercurial available for RHEL 6 is not compatible with the
# Mozilla source trees.  To work around this, a local build of a newer version
# of mercurial [3] is used.
#
# [1] https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Reference/Building_and_installing_NSS/Build_instructions
# [2] https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/JSS/Build_instructions_for_JSS_4.3.x
# [3] https://www.mercurial-scm.org/release/mercurial-${VER_HG}.tar.gz

VER_HG=2.8.1
VER_JSS=JSS_4_3_2_RTM

# set the target directory
pushd `dirname $0` &> /dev/null
    export TARGETDIR=`pwd`/target

    mkdir -p ${TARGETDIR}
    pushd ${TARGETDIR}

        # clean up previously built artifacts
        rm -fr modules mozilla

        # do local install of mercurial as the older version installed with RHEL
        # will fail with an http 414 error when pulling the mozilla sources
        if [ ! -d mercurial-${VER_HG} ]
        then
            curl -L -O \
                https://www.mercurial-scm.org/release/mercurial-${VER_HG}.tar.gz
            tar zxf mercurial-${VER_HG}.tar.gz
            cd mercurial-${VER_HG}
            make local
            cd ..
        fi

        LOCAL_HG=${TARGETDIR}/mercurial-${VER_HG}/hg

        # determine the version of the yum installed Mozilla NSS and NSPR
        # libraries
        VER_NSS=NSS_`yum list installed nss 2> /dev/null | \
          grep -i '^nss\.' | awk '{print $2}' | \
          cut -d'-' -f1 | sed 's/\./_/g'`_RTM
        VER_NSPR=NSPR_`yum list installed nspr 2> /dev/null | \
          grep -i '^nspr\.' | awk '{print $2}' | \
          cut -d'-' -f1 | sed 's/\./_/g'`_RTM

        echo ${VER_NSS} | grep -q '_0_RTM'
        if [ $? -eq 0 ]
        then
          VER_NSS=`echo ${VER_NSS} | sed 's/_0_RTM/_RTM/g'`
        fi

        echo ${VER_NSPR} | grep -q '_0_RTM'
        if [ $? -eq 0 ]
        then
          VER_NSPR=`echo ${VER_NSPR} | sed 's/_0_RTM/_RTM/g'`
        fi

        echo " nss version ${VER_NSS} installed"
        echo "nspr version ${VER_NSPR} installed"

        # build NSS and NSPR to support the JSS build only.  The yum installed
        # NSS and NSPR runtimes will actually be used by the Mozilla-JSS JCA
        # provider.

        # set options to build the libraries
        export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk.x86_64
        export BUILD_OPT=1  # comment this out for debug build
        export USE_64=1
        export NSDISTMODE=copy

        # fix missing nullptr keyword in g++ 4.4.x on RHEL 6
        export NSS_DISABLE_GTESTS=1

        #export MOZ_DEBUG_SYMBOLS=1  # uncomment for debug build

        # if we already fetched the source, just restore the clean src tree
        if [ -d mozilla.orig ]
        then
            rm -fr mozilla
            cp -fr mozilla.orig mozilla
        else
            mkdir mozilla
            cd mozilla

            ${LOCAL_HG} clone https://hg.mozilla.org/projects/jss
            cd jss
 	    ${LOCAL_HG} update ${VER_JSS}

            cd ..
            ${LOCAL_HG} clone https://hg.mozilla.org/projects/nss
            cd nss
            ${LOCAL_HG} update ${VER_NSS}

            cd ..
            ${LOCAL_HG} clone https://hg.mozilla.org/projects/nspr
            cd nspr
            ${LOCAL_HG} update ${VER_NSPR}

            cd ../..
            cp -fr mozilla mozilla.orig
        fi

        # Patch the PK11SymKey.c file to support the PBKDF2 implementation
        # in NSS.  This is a small kludge as CKM_PKCS5_PBKD2 doesn't
        # always map to DES3_KEYTYPE_FIELD, but it fits this particular
        # use case.

        patch -p0 <<END1
--- mozilla.orig/jss/security/jss/org/mozilla/jss/pkcs11/PK11SymKey.c	2014-11-13 00:26:58.220144079 -0500
+++ mozilla/jss/security/jss/org/mozilla/jss/pkcs11/PK11SymKey.c	2014-11-13 00:29:10.367186474 -0500
@@ -256,6 +256,7 @@
         typeFieldName = RC2_KEYTYPE_FIELD;
         break;
       case CKM_PBE_SHA1_DES3_EDE_CBC:
+      case CKM_PKCS5_PBKD2:
         typeFieldName = DES3_KEYTYPE_FIELD;
         break;
       case CKM_PBA_SHA1_WITH_SHA1_HMAC:
END1

        # Patch the jss.def file to expose a few other local functions
        # in the libjss4.so shared library.  These will be used by the
        # small custom native library to expose the PBKDF2 functionality
        # that's already in NSS.

        patch -p0 <<END2
--- mozilla.orig/jss/security/jss/lib/jss.def	2014-11-13 01:06:45.490880483 -0500
+++ mozilla/jss/security/jss/lib/jss.def	2014-11-13 01:19:59.584994455 -0500
@@ -326,6 +326,10 @@
 Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateECKeyPairWithOpFlags;
 Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateRSAKeyPairWithOpFlags;
 Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateDSAKeyPairWithOpFlags;
+JSS_ByteArrayToSECItem;
+JSS_PK11_getTokenSlotPtr;
+JSS_PK11_wrapSymKey;
+JSS_throwMsg;
 ;+    local:
 ;+       *;
 ;+};
END2

        # build nss and nspr to support jss build only
        cd ${TARGETDIR}/mozilla/nss
        gmake nss_build_all

        # make sure dir naming convention matches jss expectations
        for objdir in `find .. -type d -name 'Linux*'`
        do
          tgtdir=`echo $objdir | sed 's/_cc_/_/g'`
          cp -r $objdir $tgtdir
        done

        # make sure artifacts are where jss expects
        cp -r coreconf/nsinstall ../jss/security/coreconf
        cp -r ../dist ../jss

        # build native JSS library from sources
        cd ../jss/security/jss
        gmake

        # get the signed Mozilla JCE provider
        cd ${TARGETDIR}
        if [ ! -f jss4.jar ]
        then
            curl -L -O http://ftp.mozilla.org/pub/mozilla.org/security/jss/releases/${VER_JSS}/jss4.jar
        fi

	# put needed native artifacts in working directory
        cp `find ${TARGETDIR}/mozilla/jss/dist -name 'libjss4.so'` .

        # build a small native library to expose PKCS#5 PBKDF v2
        pushd ${TARGETDIR}/../nss_pbkdf2
            make clean all
            cp *.so ${TARGETDIR}
        popd

        # add jss4.jar to maven repository
        mvn install:install-file -Dfile=jss4.jar -DgroupId=org.mozilla.jss \
            -DartifactId=jss4 -Dversion=4_3_2_RTM -Dpackaging=jar

        # build the maven project
        pushd ${TARGETDIR}/../fips-compliant-vault
            mvn clean install
        popd

        # package the artifacts as a module for EAP
        mkdir -p ${TARGETDIR}/modules/org/jboss/security/fips/plugins/main/lib/linux-x86_64
        pushd ${TARGETDIR}/modules/org/jboss/security/fips/plugins/main
            cp ${TARGETDIR}/../module.xml .
            cp ${TARGETDIR}/jss4.jar .
            cp ${TARGETDIR}/../fips-compliant-vault/target/*.jar .
            cd lib/linux-x86_64
            mv ${TARGETDIR}/*.so .
        popd
    popd

    # package the artifacts into the dist folder
    mkdir -p dist/bin

    cp -r ${TARGETDIR}/modules dist
    cp fips-vault.sh dist/bin 
popd
