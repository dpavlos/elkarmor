#!/bin/bash
set -e

/usr/bin/which puppet </dev/null &>/dev/null && exit 0
/bin/rpm -ivh --replacepkgs https://yum.puppetlabs.com/puppetlabs-release-el-6.noarch.rpm
/usr/bin/yum -y install puppet
