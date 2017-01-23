#!/bin/bash

# ** define your subscription manager pool id here **
SM_POOL_ID=

# ** set the desired version of maven (whatever the latest is) **
VER_MAVEN=3.3.9

# register with RHSM
sudo subscription-manager register

# if no SM_POOL_ID defined, attempt to find the Red Hat employee
# "kitchen sink" SKU (of course, this only works for RH employees)
if [ "x${SM_POOL_ID}" = "x" ]
then
  SM_POOL_ID=`sudo subscription-manager list --available | \
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
sudo subscription-manager attach --pool="$SM_POOL_ID"
sudo subscription-manager repos --disable="*"
sudo subscription-manager repos \
  --enable=rhel-6-server-rpms \
  --enable=rhel-6-server-optional-rpms \
  --enable=rhel-6-server-supplementary-rpms

# get all updates
sudo yum -y clean all
sudo yum -y update

# install the development tools to build the JSS JNI library
sudo yum -y groupinstall 'Development tools' \
    'Server Platform Development' 'Additional Development'

# install java development tools
sudo yum -y install java-1.8.0-openjdk-devel java-1.8.0-openjdk

# install the maven distribution since we need maven to build on RHEL
curl -L -O http://download.nextag.com/apache/maven/maven-3/${VER_MAVEN}/binaries/apache-maven-${VER_MAVEN}-bin.tar.gz
sudo tar zxf apache-maven-${VER_MAVEN}-bin.tar.gz -C /opt

# add to search path
grep apache-maven-${VER_MAVEN} ~/.bash_profile &> /dev/null
if [ $? -eq 1 ]
then
  sed -i "s,\(PATH=\),\1/opt/apache-maven-${VER_MAVEN}:,g" ~/.bash_profile
fi

# restart to make sure we're running with latest updates
sudo reboot
