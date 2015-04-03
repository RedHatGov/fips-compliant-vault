fips-compliant-vault
====================

A FIPS 140-2 level 1 compliant implementation of a password vault for
Red Hat JBoss EAP 6.  This strictly means that EAP is using FIPS 140-2
level 1 certified native libraries on RHEL to provide the cryptographic
functions needed to mask sensitive strings in the EAP configuration files.
Red Hat JBoss EAP itself is not FIPS certified, but it's able to use
those certified native libraries on RHEL.

Pre-built Binaries for RHEL 6.6
-------------------------------

The dist folder included in the source distribution contains all the
required artifacts if you simply want to use this capability and skip
the build step.  Simply copy the contents of the dist folder to the home
folder for EAP (e.g. jboss-eap-6.3).

Configure Tools to Build
------------------------

This will currently only build on RHEL 6.  To set this up, run the
following script as root one time on the RHEL installation:

    post-server-install.sh

This script makes sure that RHEL 6 is fully patched with all required
development packages installed.  One package that's needed is maven
3 and it's not included in the typical RHEL distribution channels so
I used an OpenShift Enterprise 2.2 channel instead.  You can also add
maven 3 by downloading and installing manually.  Just make sure that
the command:

    mvn

is on the executable search path.

Build and Package the Custom Module
-----------------------------------

To build the java and native archives and package them up as a module,
run the following script as an unprivileged user:

    jss-setup.sh

This script does all the necessary native and java builds to enable
the vault.  The final artifacts are packaged into a module that can be
deployed to EAP.  See the dist directory when this script finishes.

Initialize and Populate the Vault
---------------------------------

To create the necessary NSS database files and populate the vault with
masked strings, please use the script:

    fips-vault.sh

This will create a directory that contains the needed NSS files and
the vault itself and then enable the user to add sensitive strings to
the vault.

EAP Configuration
-----------------

The full path to the NSS directory needs to be passed as a system
property named:

    fips.vault.path

so that JBoss can properly initialize the Mozilla NSS native library.

Mixing Vault with the SunPKCS11 SSL
-----------------------------------

The only restriction is that the same NSS database must be used for both
the SunPKCS11 provider certificates and the security vault.  The jbossweb
server SSL certificate can be imported or a self-signed certificate can
be created.  To add a self-signed certificate for the SunPKCS11 provider,
simply use:

    certutil -S -k rsa -n jbossweb -t "u,u,u" -x -s "CN=localhost, OU=MYOU, O=MYORG, L=MYCITY, ST=MYSTATE, C=MY" -d <vault-directory>

Next, create the NSS PKCS11 configuration file named 'nss_pkcs11_fips.cfg'
for the SunPKCS11 provider:

    name = nss-fips
    nssLibraryDirectory=/usr/lib64
    nssSecmodDirectory=<vault-directory>
    nssModule = fips

The vault-directory must be the full path to the vault directory which
is also read/writable and owned by the user that is running jboss.
This file can be in the user's home directory if desired so each user
id that runs JBoss can have their own NSS configuration.

As root, edit the file
'/usr/lib/jvm/java-1.7.0-openjdk.x86_64/jre/lib/security/java.security'
to enable the SunPKCS11 provider:

    #
    # List of providers and their preference orders (see above):
    #
    security.provider.1=sun.security.pkcs11.SunPKCS11 <path-to-nss-pkcs11-config-file>
    security.provider.2=sun.security.provider.Sun

Make sure to renumber the other providers.  The
path-to-nss-pkcs11-config-file parameter can use parameters to vary its
location by user.  For example, this value can be set to:

    ${user.home}/nss-pkcs11-fips.cfg

to enable each individual user running java to have their own NSS
configuration.  If you do this, take care that this file exists for each
user on the system.

Finally, in the EAP configuration file, make sure that you enable the
ssl connector:

    <connector name="https" protocol="HTTP/1.1" scheme="https" socket-binding="https" secure="true">
        <ssl name="https" key-alias="jbossweb" password="${VAULT::pkcs11::token_pin::5064667574125540400}" 
            cipher-suite="SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_anon_WITH_AES_128_CBC_SHA,TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
            keystore-type="PKCS11"/>
    </connector>

Running EAP with FIPS compliant vault
-------------------------------------

I tested EAP by using the following command line while in the $JBOSS_HOME
directory:

    bin/standalone.sh -c standalone-full.xml -Dfips.vault.path=/home/rlucente/fips-test/fips-vault

If all the configs are in agreement, you will see EAP start up cleanly
with the following entry in the server.log file:

    14:54:56,904 INFO  [org.jboss.security.fips.plugins.FIPSCompliantVault] (Controller Boot Thread) FIPS compliant password vault successfully initialized

Status 2015-04-03
-----------------

The vault is working and correctly masking/unmasking sensitive strings.
This has been confirmed to work on fully patched RHEL 6.5 and 6.6 guest
virtual machines.  The fips-vault.sh script that is used to populate
entries into the vault could definitely be improved to be more user
friendly and most importantly ask less often for the vault password.
Pull requests are welcome!

Troubleshooting
---------------

If you get an internal_ssl_error when trying to connect to the HTTPS port, please follow these [instructions](https://access.redhat.com/solutions/1309153) to exclusively use TLSv1.
