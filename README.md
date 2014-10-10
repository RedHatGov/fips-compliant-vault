fips-compliant-vault
====================

A FIPS compliant implementation of a password vault for Red Hat JBoss EAP

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

Then run the following script as an unprivileged user:

    jss-setup.sh

This script does all the necessary native and java builds to enable
the vault.  The final artifacts are packaged into a module that can be
deployed to EAP.  See the target/modules directory when this script
finishes.

To create the necessary NSS database files and pub/priv key pair in
order to test this, please use the script:

    init-vault.sh

This will create a directory that contains the needed NSS files and the
vault itself.

The full path to the NSS directory needs to be passed as a system
property named:

    fips.vault.path

so that JBoss can properly initialize the Mozilla NSS native library.

This is very early days with minimal testing.  At this point, I have
only tried this on a fully patched RHEL 6.5 guest vm.
