fips-compliant-vault
====================

A FIPS 140-2 Level 1 compliant implementation of a password vault
for Red Hat JBoss EAP 6 that works across operating systems.  This
strictly means that EAP is using FIPS 140-2 level 1 certified
libraries to provide the cryptographic functions needed to mask
sensitive strings in the EAP configuration files.  Red Hat JBoss
EAP itself is not FIPS certified, but it's able to use those certified
libraries.  This implementation takes advantage of the [Legion of
the Bouncy Castle pure java FIPS 140-2 Level 1 certified library](http://www.bouncycastle.org/fips-java/).
Huge thanks to them for their efforts getting their implementation
certified!  If you find their libraries useful, please contribute
to their ongoing efforts to maintain certification.

Disclaimer
----------

Cryptography is hard.  Doing it well requires more expertise and
special knowledge beyond the available documentation for the
underlying java and bouncy castle interfaces.  If you find a hole,
please let me know.  Seriously.  Also, if you're masking the keystore
password, be aware that this is more obfuscation than making the
password secure.  If you truly want a secure password, investigate
the alternative 'password commands' available to use host executables
or custom class files to retrieve the keystore password.

Build and Install the Vault
===========================

Configure Tools to Build
------------------------

This should build on all operating systems that support both java
and maven.  Please make sure that you have that tooling in place.
In addtion, you need to get the certified Legion of the Bouncy
Castle Java FIPS library from the [Bouncy Castle Java FIPS page](http://www.bouncycastle.org/fips-java/).
After the click-through acknowledgement, download the provider
`bc-fips-1.0.0.jar` file.  Next, add that jar file to your local maven
repository.  In a terminal window, type the following command:

    mvn install:install-file -Dfile=bc-fips-1.0.0.jar \
        -DgroupId=org.bouncycastle -DartifactId=bc-fips -Dversion=1.0.0 \
        -Dpackaging=jar

Build and Deploy the Custom Vault
---------------------------------

Building the custom vault is simple.

    git clone https://github.com/rlucente-se-jboss/fips-compliant-vault.git -b bcfips
    cd fips-compliant-vault
    mvn clean package

The results are assembled into a distribution zip file available
in `target/fips-compliant-vault-1.0.0-dist.zip`.  To deploy the
vault, unzip the distribution file into your `$JBOSS_HOME` folder:

    export JBOSS_HOME=/path/to/java-eap-6.4
    unzip -q target/fips-compliant-vault-1.0.0-dist.zip -d $JBOSS_HOME

Initialize and Populate the Vault
=================================

There are so many options and ways to setup the password vault.
This implementation also makes rekeying as painless as possible.
These instructions cover all of the options available.

Interactively Initialize an Empty Vault
---------------------------------------

To create the necessary files and populate the vault with masked
strings, please use the script without any arguments:

    $JBOSS_HOME/bin/fips-vault.sh

This will prompt the user to provide the needed parameters and store
sensitive strings in the vault.  An example session is below.  Please
note that sensitive strings are shown for illustrative purposes,
although the tool will hide these when run:
<pre>
    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/fips-vault.sh
    =========================================================================
    
      JBoss Vault
    
      JBOSS_HOME: /Users/rlucente/demo/eap-6.4/jboss-eap-6.4
    
      JAVA: java
    
    =========================================================================
    
    **********************************
    ****  JBoss Vault  ***************
    **********************************
    Please enter a Digit::   0: Start Interactive Session  1: Remove Interactive Session  2: Exit
    <b>0</b>
    Starting an interactive session

    Enter directory to store encrypted files: <b>/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault</b>

    Enter Keystore URL: <b>/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/vault.bcfks</b>
 
    Create the keystore if it doesn't exist &lt;y/N&gt; <b>y</b>
    
    Please enter the keystore password: <b>admin1jboss!</b>
    Please confirm the keystore password: <b>admin1jboss!</b>
    
    The salt must be at least 16 bytes in length, before base-64 encoding.
    Enter salt as a base-64 string (or ENTER for a random value): <b>ENTER</b>
    
    The iteration count must be at least 1000
    Enter iteration count as a number (Eg: 2000): <b>1000</b>
    
    The initialization vector must be 16 bytes in length, before base-64 encoding.
    Enter iv as a base-64 string (or ENTER for a random value): <b>ENTER</b>
    
    Enter Keystore Alias: <b>adminKey</b>
    
    Initializing Vault
    Feb 06, 2017 10:05:24 PM org.jboss.security.fips.plugins.FIPSSecurityVault setUpVault
    INFO: FIPS000373: Generating a new admin key under alias (adminKey)
    Feb 06, 2017 10:05:24 PM org.jboss.security.fips.plugins.FIPSSecurityVault init
    INFO: FIPS000361: FIPS Security Vault Implementation Initialized and Ready
    
    ******************************************************************************
    Copy the following &lt;vault/&gt; element to your standalone or domain configuration
    file to enable the password vault.
    ******************************************************************************
        ...
        &lt;/extensions&gt;
        &lt;vault code="org.jboss.security.fips.plugins.FIPSSecurityVault" module="org.jboss.security.fips" &gt;
          &lt;vault-option name="ENC_FILE_DIR" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/"/&gt;
          &lt;vault-option name="INITIALIZATION_VECTOR" value="vXpgRFPSf0qjcb9jQzSHBA=="/&gt;
          &lt;vault-option name="ITERATION_COUNT" value="1000"/&gt;
          &lt;vault-option name="KEYSTORE_ALIAS" value="adminKey"/&gt;
          &lt;vault-option name="KEYSTORE_PASSWORD" value="MASK-vFQdk4C7AVQulTRLaxBOfg=="/&gt;
          &lt;vault-option name="KEYSTORE_URL" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/vault.bcfks"/&gt;
          &lt;vault-option name="SALT" value="lL2/jeZ2Hu09C+2Tcyd9AQ=="/&gt;
        &lt;vault&gt;
        &lt;management&gt;
        ...
    ******************************************************************************
    
    Vault is initialized and ready for use
    Please enter a Digit::  0: Store a secured attribute  1: Check whether a secured attribute exists  2: Remove secured attribute  3: List all secured attributes  4: Exit
    <b>0</b>
    Task: Store a secured attribute
    
    Please enter the secured attribute value (e.g. a password): <b>admin1jboss!</b>
    Please confirm the secured attribute value (e.g. a password): <b>admin1jboss!</b>
    Enter Vault Block: <b>keystore</b>
    Enter Attribute Name: <b>password</b>
    
    ******************************************************************************
    The secured attribute value has been stored in the password vault.  Please
    make note of the following:
    ******************************************************************************
    Vault Block:keystore
    Attribute Name:password
    
    The following string should be cut/pasted wherever this password occurs in the
    EAP configuration file.  If you're changing an existing password in the vault,
    the entry in the configuration file can remain the same:
    
    ${VAULT::keystore::password::1}
    ******************************************************************************
    
    Please enter a Digit::  0: Store a secured attribute  1: Check whether a secured attribute exists  2: Remove secured attribute  3: List all secured attributes  4: Exit
    <b>4</b>
</pre>
Use the Command Line to Initialize a Vault
------------------------------------------

In this example, a single command line is used to create the vault
and store a value in it.  To see all of the options available,
simply type the commands:

    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/fips-vault.sh --help

    usage: fips-vault.sh <empty> |  [-a <arg>] [-b <arg>] -c | -h | -r | -x <arg> [-d <arg>] [-e <arg>]  [-i <arg>] [-k <arg>] [-p <arg>]  [-s <arg>] [-t] [-v <arg>]
     -a,--attribute <arg>           Attribute name
     -b,--vault-block <arg>         Vault block
     -c,--check-sec-attr            Check whether the secured attribute already exists in the vault
     -d,--alias <arg>               Vault admin key alias.  DEFAULT 'adminKey'.
     -e,--enc-dir <arg>             Directory containing encrypted files
     -h,--help                      Help
     -i,--iteration <arg>           Iteration count of at least 1000.  DEFAULT 1000.
     -k,--keystore <arg>            Keystore URL
     -p,--keystore-password <arg>   The plaintext password -OR- the base-64 encoded masked keystore password -OR- a valid password command
     -r,--remove-sec-attr           Remove secured attribute from the Vault
     -s,--salt <arg>                base-64 encoded salt of at least 128 bits in length before encoding.  DEFAULT random value generated.
     -t,--create-keystore           Automatically create keystore when it doesn't exist
     -v,--iv <arg>                  base-64 encoded initialization vector that's 128 bits in length before encoding.  DEFAULT random value generated.
     -x,--sec-attr <arg>            Add secured attribute value (such as password) to store
   
Several options have reasonable defaults and can be omitted from
the command.  The example below uses default values for alias,
iteration count, salt, and initialization vector.  This creates a
vault and stores a single attribute within it:

    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/fips-vault.sh \
        --enc-dir $JBOSS_HOME/vault \
        --keystore $JBOSS_HOME/vault/vault.bcfks \
        --create-keystore \
        --keystore-password 'admin1jboss!' \
        --vault-block keystore \
        --attribute password \
        --sec-attr 'admin1jboss!'

    =========================================================================
    
      JBoss Vault
    
      JBOSS_HOME: /Users/rlucente/demo/eap-6.4/jboss-eap-6.4
    
      JAVA: java
    
    =========================================================================
    
    Feb 06, 2017 10:37:37 PM org.jboss.security.fips.plugins.FIPSSecurityVault setUpVault
    INFO: FIPS000373: Generating a new admin key under alias (adminKey)
    Feb 06, 2017 10:37:37 PM org.jboss.security.fips.plugins.FIPSSecurityVault init
    INFO: FIPS000361: FIPS Security Vault Implementation Initialized and Ready
    
    ******************************************************************************
    The secured attribute value has been stored in the password vault.  Please
    make note of the following:
    ******************************************************************************
    Vault Block:keystore
    Attribute Name:password
    
    The following string should be cut/pasted wherever this password occurs in the
    EAP configuration file.  If you're changing an existing password in the vault,
    the entry in the configuration file can remain the same:
    
    ${VAULT::keystore::password::1}
    ******************************************************************************
    
    
    ******************************************************************************
    Copy the following <vault/> element to your standalone or domain configuration
    file to enable the password vault.
    ******************************************************************************
        ...
        </extensions>
        <vault code="org.jboss.security.fips.plugins.FIPSSecurityVault" module="org.jboss.security.fips" >
          <vault-option name="ENC_FILE_DIR" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/"/>
          <vault-option name="INITIALIZATION_VECTOR" value="b6S24evfoySTTfBxrVxl6A=="/>
          <vault-option name="ITERATION_COUNT" value="1000"/>
          <vault-option name="KEYSTORE_ALIAS" value="adminKey"/>
          <vault-option name="KEYSTORE_PASSWORD" value="MASK-e2o6hzOS+YoCTSbWF/EtRA=="/>
          <vault-option name="KEYSTORE_URL" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/vault.bcfks"/>
          <vault-option name="SALT" value="FR7kkBn+/jOFDO+t3yX1eQ=="/>
        </vault>
        <management>
        ...
    ******************************************************************************

To store another attribute in the vault, simply reuse the values
from above in the command line.  Here is an example that uses the
defaults for alias and iteration count:

    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/fips-vault.sh \
        --enc-dir $JBOSS_HOME/vault \
        --keystore $JBOSS_HOME/vault/vault.bcfks \
        --keystore-password 'MASK-e2o6hzOS+YoCTSbWF/EtRA==' \
        --salt 'FR7kkBn+/jOFDO+t3yX1eQ==' \
        --iv 'b6S24evfoySTTfBxrVxl6A==' \
        --vault-block database \
        --attribute password \
        --sec-attr 'This1$apa$$word'
    
    =========================================================================
    
      JBoss Vault
    
      JBOSS_HOME: /Users/rlucente/demo/eap-6.4/jboss-eap-6.4
    
      JAVA: java
    
    =========================================================================
    
    Feb 06, 2017 10:49:42 PM org.jboss.security.fips.plugins.FIPSSecurityVault init
    INFO: FIPS000361: FIPS Security Vault Implementation Initialized and Ready
    
    ******************************************************************************
    The secured attribute value has been stored in the password vault.  Please
    make note of the following:
    ******************************************************************************
    Vault Block:database
    Attribute Name:password
    
    The following string should be cut/pasted wherever this password occurs in the
    EAP configuration file.  If you're changing an existing password in the vault,
    the entry in the configuration file can remain the same:
    
    ${VAULT::database::password::1}
    ******************************************************************************
    
    
    ******************************************************************************
    Copy the following <vault/> element to your standalone or domain configuration
    file to enable the password vault.
    ******************************************************************************
        ...
        </extensions>
        <vault code="org.jboss.security.fips.plugins.FIPSSecurityVault" module="org.jboss.security.fips" >
          <vault-option name="ENC_FILE_DIR" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/"/>
          <vault-option name="INITIALIZATION_VECTOR" value="sk9z+FozVAilSB2oaSwLLg=="/>
          <vault-option name="ITERATION_COUNT" value="1000"/>
          <vault-option name="KEYSTORE_ALIAS" value="adminKey"/>
          <vault-option name="KEYSTORE_PASSWORD" value="MASK-FHl3O8kWrNSUjVbR0DU6Gw=="/>
          <vault-option name="KEYSTORE_URL" value="/Users/rlucente/demo/eap-6.4/jboss-eap-6.4/vault/vault.bcfks"/>
          <vault-option name="SALT" value="X7SXqofxOxjCKeTYBJ6Iew=="/>
        </vault>
        <management>
        ...
    ******************************************************************************
   
In the above example, the keystore password was supplied as a masked
base-64 encoded string with the matching salt and initialization
vector values from before.

Alternative Commands to Retrieve the Keystore Password
------------------------------------------------------

As mentioned in the disclaimer, you can also use alternative commands
to retrieve the keystore password since masking is really just
obfuscating the password.  These commands are supplied in the
keystore password parameter, whether running interactively or with
the command line.  The full syntax for the alternative commands
are:

* the masked password as a base64 string prepended with the literal 'MASK-'
* the literal '{EXT}...' where the '...' is the exact command line that will be passed to the Runtime.exec(String) method to execute a platform command. The first line of the command output is used as the password.
* the literal '{EXTC[:expiration_in_millis]}...'  The EXTC variant of EXT will cache the passwords for the optional expiration_in_millis milliseconds.  Default cache expiration is 0 = infinity.
* the literal '{CMD}...' for a general command to execute. The general command is a string delimited by ',' where the first part is the actual command and further parts represents its parameters.  The comma can be backslashed in order to keep it as the part of a parameter.
* the literal '{CMDC[:expiration_in_millis]}...'  The CMDC variant of CMD will cache the passwords for the optional expiration_in_millis milliseconds.  Default cache expiration is 0 = infinity.
* the literal '{CLASS[@modulename]}classname[:ctorargs]' where the '[:ctorargs]' is an optional string delimited by the ':' from the classname that will be passed to the classname ctor. The ctorargs itself is a comma delimited list of strings. The password is obtained from classname by invoking a 'char[] toCharArray()' method if found, otherwise, the 'String toString()'

Using Keytool to Manipulate the BCFKS Keystore
==============================================

The Bouncy Castle FIPS provider uses a special keystore type, BCFKS
(the Bouncy Castle FIPS KeyStore).  This can be used with the tool
`keytool` that is often included in java distributions.  The examples
below illustrate how to do this.

List all Entries in a BCFKS Keystore
------------------------------------

This example uses `keytool` to list all the entries in a BCFKS type
keystore.

    bash-3.2$ cd $JBOSS_HOME/vault
    bash-3.2$ keytool -list \
                      -keystore ./vault.bcfks \
                      -storepass 'admin1jboss!' \
                      -storetype BCFKS \
                      -providername BCFIPS \
                      -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
                      -v
    
    Keystore type: BCFKS
    Keystore provider: BCFIPS
    
    Your keystore contains 1 entry
    
    Alias name: adminKey
    Creation date: Feb 6, 2017
    Entry type: SecretKeyEntry
    
    
    *******************************************
    *******************************************

Add a Self-signed Certificate to a BCFKS Keystore
-------------------------------------------------

This example uses `keytool` to create and add a self-signed certificate
to a BCFKS type keystore.

    bash-3.2$ cd $JBOSS_HOME/vault
    bash-3.2$ keytool -genkeypair \
                      -alias jbossweb \
                      -keyalg RSA \
                      -keysize 3072 \
                      -dname "CN=Vault Cert, OU=JBoss, O=Red Hat, L=Raleigh, S=NC, C=US" \
                      -validity 365 \
                      -keypass 'admin1jboss!' \
                      -keystore ./vault.bcfks \
                      -storepass 'admin1jboss!' \
                      -storetype BCFKS \
                      -providername BCFIPS \
                      -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
                      -v

    Generating 3,072 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 365 days
        for: CN=Vault Cert, OU=JBoss, O=Red Hat, L=Raleigh, ST=NC, C=US
    [Storing vault.bcfks]

Combining TLS Secured Web with BCFIPS on EAP
============================================

This section contains full instructions to set up TLS secured web
listeners for both EAP 6.4 and EAP 7 using the BCFIPS password
vault.

Users may desire to run the SunJSSE provider, which contains the
SSL/TLS implementation, in FIPS 140 compliant mode.  This is often
referred to as "FIPS mode".  See full discussion [here](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/FIPS.html).  This is not
yet possible with either EAP 6 or EAP 7 due to several issues which
are tracked by this [JIRA](https://issues.jboss.org/browse/JBEAP-4120).

With EAP 6 and 7, it is possible to use the BCFIPS provider to mask
the keystore password and leverage the Bouncy Castle FIPS KeyStore
(BCFKS) to store the certificates.  Although not strictly "FIPS
mode", this does provide FIPS compliant cryptography for storing
sensitive strings combined with TLS web connections.

Override the Default java.security Policy
-----------------------------------------

Rather than modify the system-wide `$JRE_HOME/lib/security/java.security`
policy file, you can append the following to the
`$JBOSS_HOME/bin/standalone.conf` (or the `domain.conf`) file:

    # override the security providers
    JAVA_OPTS="$JAVA_OPTS -Djava.security.properties=$HOME/java.security.properties"

As discussed in this [blog](http://blog.eyallupu.com/2012/11/how-to-overriding-java-security.html) entry, each user can have their own overrides
to the default security policy file as long as that file contains
the line:

    security.overridePropertiesFile=true

By default, OpenJDK on RHEL and Oracle Java meet this criteria so
its possible to include a java option on the command line to override
the security policy file.

After making the above changes to the `$JBOSS_HOME/bin/standalone.conf`
file, copy the security providers from the default policy file to
`$HOME/java.security.properties` and add the configuration for the
BCFIPS provider as the first security provider and renumber the rest. Your
`$HOME/java.security.properties` file should resemble this:

    # We can override the values in the JRE_HOME/lib/security/java.security
    # file here.  If both properties files specify values for the same key, the
    # value from the command-line properties file is selected, as it is the last
    # one loaded.  We can reorder and change security providers in this file.
    security.provider.1=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
    security.provider.2=com.sun.net.ssl.internal.ssl.Provider
    security.provider.3=sun.security.provider.Sun
    security.provider.4=sun.security.rsa.SunRsaSign
    security.provider.5=sun.security.ec.SunEC
    security.provider.6=com.sun.crypto.provider.SunJCE
    security.provider.7=sun.security.jgss.SunProvider
    security.provider.8=com.sun.security.sasl.Provider
    security.provider.9=org.jcp.xml.dsig.internal.dom.XMLDSigRI
    security.provider.10=sun.security.smartcardio.SunPCSC
    security.provider.11=apple.security.AppleProvider

This configuration makes the Bouncy Castle provider the default
provider.  To strictly run in "FIPS mode" the Sun internal SSL
provider would need to match

    security.provider.2=com.sun.net.ssl.internal.ssl.Provider BCFIPS

however, this is not possible with both EAP 6.4 and EAP 7.0 due to
several issues tracked by this [JIRA](https://issues.jboss.org/browse/JBEAP-4120).

Copy the `bc-fips-1.0.0.jar` to the `$JRE_HOME/lib/ext` endorsed
extensions directory.

Create Vault and Add KeyStore Password
--------------------------------------

Use the command line to quickly create the vault and add the keystore password to it.

    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/fips-vault.sh \
              --enc-dir vault \
              --keystore vault/vault.bcfks \
              --create-keystore \
              --keystore-password 'admin1jboss!' \
              --vault-block keystore \
              --attribute storepass \
              --sec-attr 'admin1jboss!'

Copy the Vault Stanza to the Server Configuration
-------------------------------------------------

Edit `$JBOSS_HOME/standalone/configuration/standalone.xml` to include
the <vault/> stanza output by the above command.  Since the vault
is located in `$JBOSS_HOME/vault`, use the built-in property
`jboss.home.dir` to shorten the file paths as shown in the example
below:

    ...
    </extensions>
    <vault code="org.jboss.security.fips.plugins.FIPSSecurityVault" module="org.jboss.security.fips" >
      <vault-option name="ENC_FILE_DIR" value="${jboss.home.dir}/vault/"/>
      <vault-option name="INITIALIZATION_VECTOR" value="5kK/Fpz5TQIgPzONinLPwg=="/>
      <vault-option name="ITERATION_COUNT" value="1000"/>
      <vault-option name="KEYSTORE_ALIAS" value="adminKey"/>
      <vault-option name="KEYSTORE_PASSWORD" value="MASK-M9U4ehbH/X+qvgq1innmlg=="/>
      <vault-option name="KEYSTORE_URL" value="${jboss.home.dir}/vault/vault.bcfks"/>
      <vault-option name="SALT" value="2JLKJlkl7gvCbllh9pom/g=="/>
    </vault>
    <management>
    ...

Add the jbossweb Self-signed Certificate
----------------------------------------

Use `keytool` with the BCFIPS provider and BCFKS Keystore to add a
jbossweb self-signed certificate.

    bash-3.2$ cd $JBOSS_HOME/vault
    bash-3.2$ keytool -genkeypair \
                      -alias jbossweb \
                      -keyalg RSA \
                      -keysize 3072 \
                      -dname "CN=Vault Cert, OU=JBoss, O=Red Hat, L=Raleigh, S=NC, C=US" \
                      -validity 365 \
                      -keypass 'admin1jboss!' \
                      -keystore vault.bcfks \
                      -storepass 'admin1jboss!' \
                      -storetype BCFKS \
                      -providername BCFIPS \
                      -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
                      -v

Use the following command to verify that the secret key and the
certificate are present in the BCFKS keystore.

    bash-3.2$ cd $JBOSS_HOME/vault
    bash-3.2$ keytool -list \
                      -keystore vault.bcfks \
                      -storepass 'admin1jboss!' \
                      -storetype BCFKS \
                      -providername BCFIPS \
                      -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
                      -v

Edit the Server Configuration for EAP 6.4
-----------------------------------------

Edit the server configuration file (e.g. `standalone.xml`) to use
the BCFKS file as the keystore and get the keystore password from
the vault.  The server configuration file should have the following
stanza in the web subsystem configuration:

        ...
        <subsystem xmlns="urn:jboss:domain:web:2.2" default-virtual-server="default-host" native="false">
            <connector name="http" protocol="HTTP/1.1" scheme="http" socket-binding="http"/>
            <connector name="https" protocol="HTTP/1.1" scheme="https" socket-binding="https" secure="true">
                <ssl name="https" key-alias="jbossweb" password="${VAULT::keystore::storepass::1}" certificate-key-file="${jboss.home.dir}/vault/vault.bcfks"
                    cipher-suite="SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA, TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
                    keystore-type="BCFKS" protocol="TLSv1.2"/>
            </connector>
            <virtual-server name="default-host" enable-welcome-root="true">
            ...

Edit the Server Configuration for EAP 7.0
-----------------------------------------

Edit the server configuration file (e.g. `standalone.xml`) to use
the BCFKS file as the keystore and get the keystore password from
the vault.  The server configuration file should have the following
stanzas to add the HTTPSRealm security realm and then reference it
in the undertow https-listener:

        ...
            </security-realm>
            <security-realm name="HTTPSRealm">
                <server-identities>
                    <ssl>
                        <keystore provider="BCFKS" path="vault/vault.bcfks" relative-to="jboss.home.dir" keystore-password="${VAULT::keystore::storepass::1}" alias="jbossweb"/>
                    </ssl>
                </server-identities>
            </security-realm>
        </security-realms>
        ...
                <http-listener name="default" socket-binding="http" redirect-socket="https"/>
                <https-listener name="https" enabled-cipher-suites="SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA, TLS_ECDH_anon_WITH_AES_256_CBC_SHA" security-realm="HTTPSRealm" enabled-protocols="TLSv1.2" socket-binding="https"/>
                <host name="default-host" alias="localhost">
        ...

Test the TLS Configuration
--------------------------

Now, launch the EAP server and then browse to the secured website.
To launch the server:

    bash-3.2$ cd $JBOSS_HOME
    bash-3.2$ bin/standalone.sh

Browse to the following URL to see the secured web site leveraging
BCFKS and the vaulted keystore password:

    https://127.0.0.1:8443

Since this is a self-signed certificate, you'll need to confirm the
exception to the normal trust chains.
