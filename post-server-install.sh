#!/bin/bash

SM_POOL_ID="INSERT YOUR VALID POOL ID HERE"

# register with RHSM for updates and attach sub and channels
subscription-manager register
subscription-manager attach --pool="$SM_POOL_ID"
subscription-manager repos --disable="*"
subscription-manager repos --enable=rhel-6-server-rpms
subscription-manager repos --enable=rhel-6-server-optional-rpms
subscription-manager repos --enable=rhel-6-server-supplementary-rpms

# need maven to build this on RHEL.  this script uses an OpenShift
# channel but any valid method of installing maven 3.x should work
subscription-manager repos --enable=rhel-6-server-ose-2.1-node-rpms

# get all updates
yum clean all
yum -y update

# install the development tools to build the JSS JNI library
yum -y groupinstall 'Development tools' \
    'Server Platform Development' 'Additional Development'

# install java development tools
yum -y install java-1.7.0-openjdk-devel java-1.7.0-openjdk maven3

# restart to make sure we're running with latest updates
reboot
