#!/bin/bash
#
# Test OVS CT with vxlan traffic
#
# Require external server
#
# IGNORE_FROM_TEST_ALL

my_dir="$(dirname "$0")"
. $my_dir/common.sh
pktgen=$DIR/scapy-traffic-tester.py

require_module act_ct

REMOTE_SERVER=${1:?Require remote server}
REMOTE_NIC=${2:-ens1f0}

function ssh2() {
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o BatchMode=yes $@
}

IP=1.1.1.7
REMOTE=1.1.1.8

LOCAL_TUN=7.7.7.7
REMOTE_IP=7.7.7.8
VXLAN_ID=42

enable_switchdev_if_no_rep $REP
require_interfaces REP NIC
unbind_vfs
bind_vfs


function set_nf_liberal() {
    nf_liberal="/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal"
    if [ -e $nf_liberal ]; then
        echo 1 > $nf_liberal
        echo "`basename $nf_liberal` set to: `cat $nf_liberal`"
    else
        echo "Cannot find $nf_liberal"
    fi
}

function cleanup_remote() {
    on_remote ip a flush dev $REMOTE_NIC
    on_remote ip l del dev vxlan1 &>/dev/null
}

function cleanup() {
    ip a flush dev $NIC
    ip netns del ns0 &>/dev/null
    ip netns del ns1 &>/dev/null
    cleanup_remote
    sleep 0.5
}
trap cleanup EXIT

function config() {
    cleanup
    set_nf_liberal
    conntrack -F
    ifconfig $NIC $LOCAL_TUN/24 up
    # WA SimX bug? interface not receiving traffic from tap device to down&up to fix it.
    for i in $NIC $VF $REP ; do
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

function on_remote() {
    local cmd=$@
    ssh2 $REMOTE_SERVER $cmd
}

function config_remote() {
    on_remote ip link del vxlan1 2>/dev/null
    on_remote ip link add vxlan1 type vxlan id $VXLAN_ID dev $REMOTE_NIC dstport 4789
    on_remote ip a flush dev $REMOTE_NIC
    on_remote ip a add $REMOTE_IP/24 dev $REMOTE_NIC
    on_remote ip a add $REMOTE/24 dev vxlan1
    on_remote ip l set dev vxlan1 up
    on_remote ip l set dev $REMOTE_NIC up
}

function add_openflow_rules() {
    ovs-ofctl del-flows br-ovs
    ovs-ofctl add-flow br-ovs arp,actions=normal
    ovs-ofctl add-flow br-ovs icmp,actions=normal
    ovs-ofctl add-flow br-ovs "table=0, udp,ct_state=-trk actions=ct(table=1)"
    ovs-ofctl add-flow br-ovs "table=1, udp,ct_state=+trk+new actions=ct(commit),normal"
    ovs-ofctl add-flow br-ovs "table=1, udp,ct_state=+trk+est actions=normal"
    ovs-ofctl dump-flows br-ovs --color
}

function stop() {
    echo "stop"
    kill $pid1 &>/dev/null
    kill $pid2 &>/dev/null
    echo "wait for bgs"
    wait &>/dev/null
}

function run() {
    config
    config_remote
    add_openflow_rules

    # icmp
    ip netns exec ns0 ping -q -c 1 -i 0.1 -w 1 $REMOTE
    if [ $? -ne 0 ]; then
        err "ping failed"
        return
    fi

    t=20
    port_count=8000
    # traffic
    ssh2 $REMOTE_SERVER $pktgen -i vxlan1 --src-ip $REMOTE --src-port 1000 --src-port-count $port_count --dst-port $port_count --dst-port-count 1 --pkt-count 1 --inter 0 --dst-ip $IP --time $t &
    pid1=$!
    sleep 4
    ip netns exec ns0 $pktgen -i $VF --src-ip $IP --src-port $port_count --src-port-count 1 --dst-port 1000 --dst-port-count $port_count --pkt-count 1 --inter 0 --dst-ip $REMOTE --time $t &
    pid2=$!

    # verify pid
    sleep 2
    kill -0 $pid1 &>/dev/null
    if [ $? -ne 0 ]; then
        err "pktgen server failed"
        stop
        return
    fi
    kill -0 $pid2 &>/dev/null
    if [ $? -ne 0 ]; then
        err "pktgen client failed"
        stop
        return
    fi
    echo "pids ok"

    sleep $t

    count=`conntrack -L | grep ASSURED | wc -l`
    echo "flows: $count"
    if [ "$count" -lt $port_count ]; then
        err "Expected at least $port_count flows"
    fi

    stop
    # wait for ovs aging (default 10)
    sleep 12
}

run
start_clean_openvswitch
test_done