fips-compliant-vault
====================

A FIPS compliant implementation of a password vault for Red Hat JBoss EAP

To set this up, please run the scripts in this order:

    post-server-install.sh
    jss-setup.sh

The first script, post-server-install.sh, makes sure that RHEL 6 is fully
patched with all required development packages installed.  One package
that's needed is maven 3 and it's not included in the typical RHEL
distribution channels so I used an OpenShift Enterprise 2.1 channel
instead.  You can also add maven 3 by downloading and installing manually.

The second script, jss-setup.sh, does all the necessary native and java
builds to enable the vault.  The final artifacts are packaged into a
module that can be deployed to EAP.  See the target/modules directory.

The init-vault.sh script will create the necessary NSS database files
and pub/priv key pair in order to test this.

This is very early days with minimal testing.  At this point, I have
only tried this on a fully patched RHEL 6.5 guest vm.
