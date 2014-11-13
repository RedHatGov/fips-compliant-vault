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
I used an OpenShift Enterprise 2.1 channel instead.  You can also add
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

Caveat
------

This is very early days and testing continues.  The functionality appears
to work with only small changes remaining such as substitution strings
for vaulted values.  At this point, I have only tried this on a fully
patched RHEL 6.6 guest vm.  Pull requests are welcome!
