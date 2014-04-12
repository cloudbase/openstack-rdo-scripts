#!/bin/bash
set -e

if [ $# -lt 8 ] || [ $(($# % 2)) = 1 ]; then
    echo "Usage: $0 <openstack_release> <ssh_key_file> <controller_host_name> <controller_host_ip> <network_host_name> <network_host_ip> [<qemu_compute_host_name> <qemu_compute_host_ip>]+"
    exit 1
fi

OPENSTACK_RELEASE=$1

SSH_KEY_FILE=$2

CONTROLLER_VM_NAME=$3
CONTROLLER_VM_IP=$4
NETWORK_VM_NAME=$5
NETWORK_VM_IP=$6

i=0
QEMU_COMPUTE_VM_NAMES=()
QEMU_COMPUTE_VM_IPS=()
for val in ${@:7}
do
   if [ $(($i % 2)) = 0 ]; then
       QEMU_COMPUTE_VM_NAMES+=($val)
   else
       QEMU_COMPUTE_VM_IPS+=($val)
   fi
   ((i++))
done

RDO_ADMIN=root
RDO_ADMIN_PASSWORD=Passw0rd

ANSWERS_FILE=packstack_answers.conf
NOVA_CONF_FILE=/etc/nova/nova.conf
CEILOMETER_CONF_FILE=/etc/ceilometer/ceilometer.conf

DOMAIN=localdomain

MAX_WAIT_SECONDS=600

BASEDIR=$(dirname $0)

. $BASEDIR/utils.sh

if [ ! -f "$SSH_KEY_FILE" ]; then
    ssh-keygen -q -t rsa -f $SSH_KEY_FILE -N "" -b 4096
fi
SSH_KEY_FILE_PUB=$SSH_KEY_FILE.pub

echo "Configuring SSH public key authentication on the RDO hosts"

configure_ssh_pubkey_auth $RDO_ADMIN $CONTROLLER_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
configure_ssh_pubkey_auth $RDO_ADMIN $NETWORK_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD

for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    configure_ssh_pubkey_auth $RDO_ADMIN $QEMU_COMPUTE_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
done

echo "Sync hosts date and time"
update_host_date $RDO_ADMIN@$CONTROLLER_VM_IP
update_host_date $RDO_ADMIN@$NETWORK_VM_IP

for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    update_host_date $RDO_ADMIN@$QEMU_COMPUTE_VM_IP
done

config_openstack_network_adapter () {
    SSHUSER_HOST=$1
    ADAPTER=$2
    IPADDR=$3
    NETMASK=$4

    run_ssh_cmd_with_retry $SSHUSER_HOST "cat << EOF > /etc/sysconfig/network-scripts/ifcfg-$ADAPTER
DEVICE="$ADAPTER"
BOOTPROTO="none"
MTU="1500"
ONBOOT="yes"
IPADDR="$IPADDR"
NETMASK="$NETMASK"
EOF"

    run_ssh_cmd_with_retry $SSHUSER_HOST "ifup $ADAPTER"
}

set_fake_iface_for_rdo_neutron_bug () {
    local SSHUSER_HOST=$1
    local IFACE=$2

    run_ssh_cmd_with_retry $SSHUSER_HOST "ip link set name $IFACE dev dummy0 && ip addr add 10.8.100.2/24 dev $IFACE && ifconfig $IFACE up"
}

echo "Configuring networking"

DATA_IP_BASE=10.13.8
DATA_IP_NETMASK=255.255.255.0
NETWORK_VM_DATA_IP=$DATA_IP_BASE.1

set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$CONTROLLER_VM_IP eth0
set_hostname $RDO_ADMIN@$CONTROLLER_VM_IP $CONTROLLER_VM_NAME.$DOMAIN $CONTROLLER_VM_IP
# See https://bugs.launchpad.net/packstack/+bug/1307018
set_fake_iface_for_rdo_neutron_bug $RDO_ADMIN@$CONTROLLER_VM_IP eth1

config_openstack_network_adapter $RDO_ADMIN@$NETWORK_VM_IP eth1 $NETWORK_VM_DATA_IP $DATA_IP_NETMASK
config_openstack_network_adapter $RDO_ADMIN@$NETWORK_VM_IP eth2
set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$NETWORK_VM_IP eth0
set_hostname $RDO_ADMIN@$NETWORK_VM_IP $NETWORK_VM_NAME.$DOMAIN $NETWORK_VM_IP

i=0
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    QEMU_COMPUTE_VM_NAME=${QEMU_COMPUTE_VM_NAMES[$i]}
    QEMU_COMPUTE_VM_DATA_IP=$DATA_IP_BASE.$(($i+2))

    config_openstack_network_adapter $RDO_ADMIN@$QEMU_COMPUTE_VM_IP eth1 $QEMU_COMPUTE_VM_DATA_IP $DATA_IP_NETMASK
    set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$QEMU_COMPUTE_VM_IP eth0
    set_hostname $RDO_ADMIN@$QEMU_COMPUTE_VM_IP $QEMU_COMPUTE_VM_NAME.$DOMAIN $QEMU_COMPUTE_VM_IP

    ((i++))
done

echo "Validating network configuration"

set_test_network_config () {
    SSHUSER_HOST=$1
    IFADDR=$2
    ACTION=$3

    if check_interface_exists $SSHUSER_HOST br-eth1; then
        IFACE=br-eth1
    else
        IFACE=eth1
    fi

    set_interface_ip $SSHUSER_HOST $IFACE $IFADDR $ACTION
}

i=0
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    QEMU_COMPUTE_VM_DATA_IP=$DATA_IP_BASE.$(($i+2))

    ping_ip $RDO_ADMIN@$NETWORK_VM_IP $QEMU_COMPUTE_VM_DATA_IP
    ping_ip $RDO_ADMIN@$QEMU_COMPUTE_VM_IP $NETWORK_VM_DATA_IP

    ((i++))
done

# TODO: Check external network

echo "Installing RDO RPMs on controller"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y http://rdo.fedorapeople.org/openstack/openstack-$OPENSTACK_RELEASE/rdo-release-$OPENSTACK_RELEASE.rpm || true"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y openstack-packstack"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum -y install http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm || true"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y crudini"

echo "Generating Packstack answer file"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "packstack --gen-answer-file=$ANSWERS_FILE"

echo "Configuring Packstack answer file"

QEMU_COMPUTE_VM_IP_LIST=""
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    if [ "$QEMU_COMPUTE_VM_IP_LIST" ]; then
        QEMU_COMPUTE_VM_IP_LIST+=","
    fi
    QEMU_COMPUTE_VM_IP_LIST+=$QEMU_COMPUTE_VM_IP
done

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "\
crudini --set $ANSWERS_FILE general CONFIG_SSH_KEY /root/.ssh/id_rsa.pub && \
crudini --set $ANSWERS_FILE general CONFIG_NTP_SERVERS 0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org && \
crudini --set $ANSWERS_FILE general CONFIG_CINDER_VOLUMES_SIZE 20G && \
crudini --set $ANSWERS_FILE general CONFIG_NOVA_COMPUTE_HOSTS $QEMU_COMPUTE_VM_IP_LIST && \
crudini --del $ANSWERS_FILE general CONFIG_NOVA_NETWORK_HOST"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "\
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_L3_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_DHCP_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_METADATA_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TENANT_NETWORK_TYPE gre && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TUNNEL_RANGES 1:1000 && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TUNNEL_IF eth1"

echo "Deploying SSH private key on $CONTROLLER_VM_IP"

scp -i $SSH_KEY_FILE -o 'PasswordAuthentication no' $SSH_KEY_FILE $RDO_ADMIN@$CONTROLLER_VM_IP:.ssh/id_rsa
scp -i $SSH_KEY_FILE -o 'PasswordAuthentication no' $SSH_KEY_FILE_PUB $RDO_ADMIN@$CONTROLLER_VM_IP:.ssh/id_rsa.pub

echo "Running Packstack"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "packstack --answer-file=$ANSWERS_FILE"

echo "Workaround for Neutron OVS agent bug on controller"

disable_neutron_ovs_agent () {
    local SSHUSER_HOST=$1
    local AGENTHOSTNAME=$2
    run_ssh_cmd_with_retry $SSHUSER_HOST "service neutron-openvswitch-agent stop"
    run_ssh_cmd_with_retry $SSHUSER_HOST "chkconfig neutron-openvswitch-agent off"
    local AGENTID=`run_ssh_cmd_with_retry $SSHUSER_HOST "source ./keystonerc_admin && neutron agent-list | grep 'Open vSwitch agent' | grep $AGENTHOSTNAME" | awk '{print $2}'`
    run_ssh_cmd_with_retry $SSHUSER_HOST "source ./keystonerc_admin && neutron agent-delete $AGENTID"
}

# See: https://bugs.launchpad.net/packstack/+bug/1307018
disable_neutron_ovs_agent $RDO_ADMIN@$CONTROLLER_VM_IP $CONTROLLER_VM_NAME.$DOMAIN

echo "Additional firewall rules"

# See https://github.com/stackforge/packstack/commit/ca46227119fd6a6e5b0f1ef19e8967d92a3b1f6c
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 9696 -j ACCEPT"
done

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 9696 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 35357 -j ACCEPT"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iptables save"

echo "Disabling Nova API rate limits"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "crudini --set $NOVA_CONF_FILE DEFAULT api_rate_limit False"

echo "Enabling Neutron firewall driver on controller"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i 's/^#\ firewall_driver/firewall_driver/g' /etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini && service neutron-server restart"

echo "Set libvirt_type on QEMU/KVM compute node"
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$QEMU_COMPUTE_VM_IP "grep vmx /proc/cpuinfo > /dev/null && crudini --set $NOVA_CONF_FILE DEFAULT libvirt_type kvm || true"
done

echo "Applying additional OVS configuration on $NETWORK_VM_IP"

run_ssh_cmd_with_retry $RDO_ADMIN@$NETWORK_VM_IP "ovs-vsctl list-ports br-ex | grep eth2 || ovs-vsctl add-port br-ex eth2"

echo "Rebooting Linux nodes to load the new kernel"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP reboot
run_ssh_cmd_with_retry $RDO_ADMIN@$NETWORK_VM_IP reboot

for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$QEMU_COMPUTE_VM_IP reboot
done

echo "Wait for reboot"
sleep 120

echo "Waiting for SSH to be available on $CONTROLLER_VM_IP"
wait_for_listening_port $CONTROLLER_VM_IP 22 $MAX_WAIT_SECONDS

echo "Validating Nova configuration"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && nova service-list | sed -e '$d' | awk '(NR > 3) {print $10}' | sed -rn '/down/q1'" 10

echo "Validating Neutron configuration"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && neutron agent-list -f csv | sed -e '1d' | sed -rn 's/\".*\",\".*\",\".*\",\"(.*)\",.*/\1/p' | sed -rn '/xxx/q1'" 10

echo "RDO installed!"
echo "SSH access:"
echo "ssh -i $SSH_KEY_FILE $RDO_ADMIN@$CONTROLLER_VM_IP"
