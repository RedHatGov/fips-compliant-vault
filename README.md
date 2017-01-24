fips-compliant-vault
====================

A FIPS 140-2 level 1 compliant implementation of a password vault for
Red Hat JBoss EAP 6.  This strictly means that EAP is using FIPS 140-2
level 1 certified native libraries on RHEL to provide the cryptographic
functions needed to mask sensitive strings in the EAP configuration files.
Red Hat JBoss EAP itself is not FIPS certified, but it's able to use
those certified native libraries on RHEL.

Pre-built Binaries for RHEL 6.8
-------------------------------

The dist folder included in the source distribution contains all the
required artifacts if you simply want to use this capability and skip
the build step.  Simply copy the contents of the dist folder to the home
folder for EAP (e.g. jboss-eap-6.4).

Configure Tools to Build
------------------------

This will currently only build on RHEL 6.  To set this up, run the
following script as an unprivileged user one time on the RHEL installation
(the user should have sudo access for this):

    ./post-server-install.sh

This script makes sure that RHEL 6 is fully patched with all required
development packages installed.  One package that's needed is maven 3
and it's not included in the typical RHEL distribution channels so the
above script downloads and installs it from the Apache Maven web site.
Maven is also added to the user's executable search path.  Make sure
that the command: Just make sure that the command:

    mvn -v

works correctly after running the above script.

Build and Package the Custom Module
-----------------------------------

To build the java and native archives and package them up as a module,
run the following script as an unprivileged user:

    ./jss-setup.sh

This script does all the necessary native and java builds to enable
the vault.  The final artifacts are packaged into bin and modules
directories that can be deployed to EAP.  To deploy these artifacts,
do the following:

    cd dist
    cp -r dist/* $JBOSS_HOME

where JBOSS_HOME is the top-level JBoss EAP installation directory.

Initialize and Populate the Vault
---------------------------------

To create the necessary NSS database files and populate the vault with
masked strings, please use the script:

    $JBOSS_HOME/bin/fips-vault.sh

This will create a directory that contains the needed NSS files and
the vault itself and then enable the user to add sensitive strings to
the vault.

EAP Configuration
-----------------

The full path to the NSS directory needs to be passed as a system
property named:

    fips.vault.path

so that JBoss can properly initialize the Mozilla NSS native library.
You can add this to the `$JBOSS_HOME/bin/standalone.conf` file so that
you don't have to specify it on the command line.  Simply append the
following to the bottom of the `$JBOSS_HOME/bin/standalone.conf` file:

    # set the fips vault path
    JAVA_OPTS="$JAVA_OPTS -Dfips.vault.path=$HOME/nssdb"


Mixing Vault with the SunPKCS11 SSL
-----------------------------------

The web container (JBoss Web) of JBoss EAP 6 can be configured to
use FIPS 140-2 compliant cryptography for SSL.  This can also be
combined with the password vault.

First, make sure that RHEL 6 has been configured for FIPS 140-2
compliance based on this [solution article](https://access.redhat.com/knowledge/solutions/137833).

To configure EAP to comply with FIPS 140-2 for SSL/TLS, please
follow the instructions in section 4.9.4 of the [Security
Guide](https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/6.4/html-single/Security_Guide/#sect-FIPS_140-2_Compliant_Encryption).  Important changes to these instructions are noted below.

CHANGE TO STEP 1:  The vault directory *is* the NSS database that
will be used.  You can skip this step.

CHANGE TO STEP 2:  Create the NSS PKCS11 configuration file named
'nss-pkcs11-fips.cfg' for the SunPKCS11 provider:

    name = nss-fips
    nssLibraryDirectory=/usr/lib64
    nssSecmodDirectory=<vault-directory>
    nssModule = fips

The vault-directory must be the full path to the vault directory
which is also read/writable and owned by the user that is running
jboss.  This will be the same as the NSS database directory when
combining the vault with the SunPKCS11 FIPS compliant encryption.
This file can be in the user's home directory if desired so each
user id that runs JBoss can have their own NSS configuration.

CHANGE TO STEP 3:  There are two ways to configure the java.security
policy file and set the security providers.  The first is a system-wide
change that applies to all users the second is a user-specific change
so that each java user can have their own policy.

CHANGE TO STEP 3 (Option 1):  As root, edit the file
'/usr/lib/jvm/java-1.8.0-openjdk.x86_64/jre/lib/security/java.security'
to enable the SunPKCS11 provider:

    #
    # List of providers and their preference orders (see above):
    #
    security.provider.1=sun.security.pkcs11.SunPKCS11 <path-to-nss-pkcs11-config-file>
    security.provider.2=sun.security.provider.Sun

Make sure to renumber the other providers.  The
path-to-nss-pkcs11-config-file parameter can use parameters to vary
its location by user.  For example, this value can be set to:

    ${user.home}/nss-pkcs11-fips.cfg

to enable each individual user running java to have their own NSS
configuration and NSS database.  If you do this, take care that
this file exists for each user on the system.

CHANGE TO STEP 3 (Option 2): Alternatively, you can give each java user
their own security policy and NSS database configuration.  Rather than
modify the system-wide `$JRE_HOME/lib/security/java.security` policy file,
you can append the following to the `$JBOSS_HOME/bin/standalone.conf`
file:

    # override the security providers
    JAVA_OPTS="$JAVA_OPTS -Djava.security.properties=$HOME/java.security.properties"

According to this [blog
entry](http://blog.eyallupu.com/2012/11/how-to-overriding-java-security.html),
each user can have their own overrides to the default security policy
file as long as that file contains the line:

    security.overridePropertiesFile=true

By default, OpenJDK on RHEL meets this criteria so its possible to include
a java option on the command line to override the security policy file.
After making the above changes to the `$JBOSS_HOME/bin/standalone.conf`
file, copy the security providers from the default policy file to
`$HOME/java.security.properties` and add the configuration for the
SunPKCS11 provider as the first security provider and renumber the rest.
Your `$HOME/java.security.properties` file should resemble this:

    # We can override the values in the JRE_HOME/lib/security/java.security
    # file here.  If both properties files specify values for the same key, the
    # value from the command-line properties file is selected, as it is the last
    # one loaded.  We can reorder and change security providers in this file.
    security.provider.1=sun.security.pkcs11.SunPKCS11 ${user.home}/nss-pkcs11-fips.cfg
    security.provider.2=sun.security.provider.Sun
    security.provider.3=sun.security.rsa.SunRsaSign
    security.provider.4=sun.security.ec.SunEC
    security.provider.5=com.sun.net.ssl.internal.ssl.Provider
    security.provider.6=com.sun.crypto.provider.SunJCE
    security.provider.7=sun.security.jgss.SunProvider
    security.provider.8=com.sun.security.sasl.Provider
    security.provider.9=org.jcp.xml.dsig.internal.dom.XMLDSigRI
    security.provider.10=sun.security.smartcardio.SunPCSC

CHANGE TO STEP 4:  Skip this step since the fips-vault.sh script
already does this.

CHANGE TO STEP 5:  Skip this step since the fips-vault.sh script
already does this.

CHANGE TO STEP 6:  The jbossweb server SSL certificate can be
imported or a self-signed certificate can be created.  To add a
self-signed certificate for the SunPKCS11 provider, simply use:

    certutil -S -k rsa -n jbossweb -t "u,u,u" -x -s "CN=localhost, OU=MYOU, O=MYORG, L=MYCITY, ST=MYSTATE, C=MY" -d <vault-directory>

CHANGE TO STEP 7:  Finally, in the EAP configuration file, make
sure that you enable the ssl connector.  You can run the CLI commands
or simply edit the standalone configuration file to match the
following:

    <connector name="https" protocol="HTTP/1.1" scheme="https" socket-binding="https" secure="true">
        <ssl name="https" key-alias="jbossweb" password="${VAULT::pkcs11::token_pin::5064667574125540400}" 
            cipher-suite="SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_anon_WITH_AES_128_CBC_SHA,TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
            keystore-type="PKCS11"/>
    </connector>

Running EAP with FIPS compliant vault
-------------------------------------

I tested EAP by using the following command line, with the configuration
changes from option 2 of Step 3 above:

    $JBOSS_HOME/bin/standalone.sh -c standalone-full.xml

If all the configs are in agreement, you will see EAP start up cleanly
with the following entry in the server.log file:

    14:54:56,904 INFO  [org.jboss.security.fips.plugins.FIPSCompliantVault] (Controller Boot Thread) FIPS compliant password vault successfully initialized

Status 2017-01-24
-----------------

The vault is working and correctly masking/unmasking sensitive strings
with EAP 6.4.  This has been confirmed to work on fully patched
RHEL 6.8 guest virtual machine and EAP 6.4 CP12.

The fips-vault.sh script that is used to populate entries into the
vault could definitely be improved to be more user friendly and
most importantly ask less often for the vault password.  Pull
requests are welcome!

Troubleshooting
---------------

If you get an internal_ssl_error when trying to connect to the HTTPS port,
please follow these [instructions](https://access.redhat.com/solutions/1309153) to exclusively use TLSv1.  Look in the
comments to that article for EAP 6 instructions.
