#!/bin/bash

# TODO: Make the script smart enough to know on which OS is running
#       and use appropiate tools to install dependencies.
#
# For now it only works on CentOS.

echo "Installing dependencies."

yum install -y git expect nc

echo "Generating SSH keys for Deployment."

ssh-keygen -q -t rsa -f ~/.ssh/id_rsa_rdo -N "" -b 4096

echo "Cloning Cloudbase openstack-rdo-scripts."

git clone https://github.com/cloudbase/openstack-rdo-scripts

cat <<EOF 

Now you can deploy using the following command:

~/openstack-rdo-scripts/configure-rdo-multi-node.sh havana ~/.ssh/id_rsa_rdo rdo-controller controller.ip.addr.ess rdo-network network.ip.addr.ess rdo-kvm kvm.ip.addr.ess rdo-hyperv hyperv.ip.addr.ess"

EOF
