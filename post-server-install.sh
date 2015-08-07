#!/bin/bash

# ** define your subscription manager pool id here **
SM_POOL_ID=

# register with RHSM
subscription-manager register

# if no SM_POOL_ID defined, attempt to find the Red Hat employee
# "kitchen sink" SKU (of course, this only works for RH employees)
if [ "x${SM_POOL_ID}" = "x" ]
then
  SM_POOL_ID=`subscription-manager list --available | \
      grep 'Subscription Name:\|Pool ID:\|System Type' | \
      grep -B2 'Virtual' | \
      grep -A1 'Employee SKU' | \
      grep 'Pool ID:' | awk '{print $3}'`

  # exit if none found
  if [ "x${SM_POOL_ID}" = "x" ]
  then
    echo "No subcription manager pool id found.  Exiting"
    exit 1
  fi
fi

# attach subscription pool and enable channels for updates
subscription-manager attach --pool="$SM_POOL_ID"
subscription-manager repos --disable="*"
subscription-manager repos --enable=rhel-6-server-rpms
subscription-manager repos --enable=rhel-6-server-optional-rpms
subscription-manager repos --enable=rhel-6-server-supplementary-rpms

# need maven to build this on RHEL.  this script uses an OpenShift
# channel but any valid method of installing maven 3.x should work
subscription-manager repos --enable=rhel-6-server-ose-2.2-node-rpms

# get all updates
yum clean all
yum -y update

# install the development tools to build the JSS JNI library
yum -y groupinstall 'Development tools' \
    'Server Platform Development' 'Additional Development'

# install java development tools
yum -y install java-1.7.0-openjdk-devel java-1.7.0-openjdk maven3 wget

# restart to make sure we're running with latest updates
reboot
