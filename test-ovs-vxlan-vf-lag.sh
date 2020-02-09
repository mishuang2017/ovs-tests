#!/bin/bash
#
# Test OVS with vxlan traffic and VF LAG
#
# Bug SW #2062685: [ASAP, OFED 5.0, centos 7.2(default kernel), fw_steering] vxlan traffic over lag is not offloaded
#
# Require external server
#
# IGNORE_FROM_TEST_ALL

my_dir="$(dirname "$0")"
. $my_dir/common.sh

REMOTE_SERVER=${1:?Require remote server}
REMOTE_NIC=${2:-ens1f0}
REMOTE_NIC2=${3:-ens1f1}

require_remote_server

IP=1.1.1.7
REMOTE=1.1.1.8

LOCAL_TUN=7.7.7.7
REMOTE_IP=7.7.7.8
VXLAN_ID=42


function config_ports() {
    config_sriov 2
    config_sriov 2 $NIC2
    enable_switchdev_if_no_rep $REP
    enable_switchdev $NIC2
    require_interfaces REP NIC
    unbind_vfs
    config_bonding $NIC $NIC2
    bind_vfs
}

function cleanup_remote() {
    on_remote ip link set dev $REMOTE_NIC nomaster &>/dev/null
    on_remote ip link set dev $REMOTE_NIC2 nomaster &>/dev/null
    on_remote ip link del bond0 &>/dev/null
    on_remote "ip a flush dev $REMOTE_NIC ; ip a flush dev $REMOTE_NIC2 ; ip l del dev vxlan1 &>/dev/null"
}

function cleanup() {
    cleanup_remote
    ip netns del ns0 &>/dev/null
    ip netns del ns1 &>/dev/null
    sleep 0.5
    unbind_vfs
    sleep 1
    clear_bonding
    config_sriov 0 $NIC2
    ip a flush dev $NIC
}
trap cleanup EXIT

function config() {
    cleanup
    config_ports
    ifconfig bond0 $LOCAL_TUN/24 up
    # WA SimX bug? interface not receiving traffic from tap device to down&up to fix it.
    for i in bond0 $NIC $VF $REP ; do
            ifconfig $i down
            ifconfig $i up
            reset_tc $i
    done
    ip netns add ns0
    ip link set dev $VF netns ns0
    ip netns exec ns0 ifconfig $VF $IP/24 up

    echo "Restarting OVS"
    start_clean_openvswitch

    ovs-vsctl add-br br-ovs
    ovs-vsctl add-port br-ovs $REP
    ovs-vsctl add-port br-ovs vxlan1 -- set interface vxlan1 type=vxlan options:local_ip=$LOCAL_TUN options:remote_ip=$REMOTE_IP options:key=$VXLAN_ID options:dst_port=4789
}

function config_remote_bonding() {
    local nic1=$REMOTE_NIC
    local nic2=$REMOTE_NIC2
    on_remote ip link add name bond0 type bond || fail "Failed to create bond interface"
    on_remote ip link set dev bond0 type bond || fail "Failed to set bond mode"
    on_remote "echo active-backup > /sys/class/net/bond0/bonding/mode"
    on_remote ip link set dev $nic1 down
    on_remote ip link set dev $nic2 down
    on_remote ip link set dev $nic1 master bond0
    on_remote ip link set dev $nic2 master bond0
    on_remote ip link set dev bond0 up
    on_remote ip link set dev $nic1 up
    on_remote ip link set dev $nic2 up
    sleep 1
}


function config_remote() {
    on_remote ip link del vxlan1 2>/dev/null
    config_remote_bonding
    on_remote ip link add vxlan1 type vxlan id $VXLAN_ID dev bond0 dstport 4789
    on_remote ip a add $REMOTE_IP/24 dev bond0
    on_remote ip a add $REMOTE/24 dev vxlan1
    on_remote ip l set dev vxlan1 up
    on_remote ip l set dev bond0 up
}

function test_tcpdump() {
    local pid=$1
    wait $pid
    local rc=$?
    if [[ $rc -eq 124 ]]; then
        :
    elif [[ $rc -eq 0 ]]; then
        err "Didn't expect to see packets"
    else
        err "Tcpdump failed"
    fi
}

function run_server() {
    ssh2 $REMOTE_SERVER timeout $((t+2)) iperf -s -t $t &
    pk1=$!
    sleep 0.5
}

function run_client() {
    ip netns exec ns0 timeout $((t+2)) iperf -c $REMOTE -t $t -P3 &
    pk2=$!
}

function kill_traffic() {
    kill -9 $pk1 &>/dev/null
    kill -9 $pk2 &>/dev/null
    wait $pk1 $pk2 2>/dev/null
}

function run() {
    config
    config_remote

    if [ "$B2B" == 1 ]; then
        # set local and remote to the same port
        echo $active_slave > /sys/class/net/bond0/bonding/active_slave
        on_remote "echo $remote_active > /sys/class/net/bond0/bonding/active_slave"
    fi

    # icmp
    ip netns exec ns0 ping -q -c 1 -i 0.1 -w 1 $REMOTE
    if [ $? -ne 0 ]; then
        err "ping failed"
        return
    fi

    t=15
    # traffic
    run_server
    run_client

    # verify pid
    sleep 2
    kill -0 $pk1 &>/dev/null
    p1=$?
    kill -0 $pk2 &>/dev/null
    p2=$?
    if [ $p1 -ne 0 ] || [ $p2 -ne 0 ]; then
        err "traffic failed"
        return
    fi

    timeout $((t-4)) tcpdump -qnnei $REP -c 10 'tcp' &
    tpid=$!

    sleep $t
    title "Verify traffic is offloaded"
    test_tcpdump $tpid

    i=0 && mlxdump -d $PCI fsdump --type FT --gvmi=$i --no_zero > /tmp/port$i
    i=1 && mlxdump -d $PCI fsdump --type FT --gvmi=$i --no_zero > /tmp/port$i

    kill_traffic
    echo "wait for bgs"
    wait

    iterate_bond_slaves
}

function iterate_bond_slaves() {
    title "Iterate bond slaves"
    for i in `seq 5`; do
        title "Iter $i"
        change_slaves
        count1=`get_rx_pkts $slave1`
        t=10
        run_server
        run_client
        sleep 2
        echo "wait"
        sleep $t
        kill_traffic
        wait
        count2=`get_rx_pkts $slave1`
        ((count1+=100))
        if [ "$count2" -lt "$count1" ]; then
            err "No traffic?"
        fi
    done
}

slave1=$NIC
slave2=$NIC2
active_slave=$NIC
remote_active=$REMOTE_NIC
function change_slaves() {
    log "change active slave from $slave1 to $slave2"
    local tmpslave=$slave1
    slave1=$slave2
    slave2=$tmpslave
    ifconfig $tmpslave down
    sleep 0.5
    ifconfig $tmpslave up

    if [ "$B2B" == 1 ]; then
        if [ "$remote_active" == $REMOTE_NIC ]; then
            remote_active=$REMOTE_NIC2
        else
            remote_active=$REMOTE_NIC
        fi
        on_remote "echo $remote_active > /sys/class/net/bond0/bonding/active_slave"
    fi
}

start_check_syndrome
run
start_clean_openvswitch
cleanup
check_syndrome
trap - EXIT
test_done