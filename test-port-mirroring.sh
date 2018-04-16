#!/bin/bash
#
# Verify the port mirroring functionality
#

NIC=${1:-enp4s0f0}

VF1=${2:-enp4s0f2}
VF2=${3:-enp4s0f3}
VF3=${4:-enp4s0f4}

REP1=${5:-${NIC}_0}
REP2=${6:-${NIC}_1}
REP3=${7:-${NIC}_2}

my_dir="$(dirname "$0")"
. $my_dir/common.sh

NS1_IP=1.1.1.11
NS2_IP=1.1.1.12

BR=ov1
HOST1_VXLAN=vxlan0
HOST2_VXLAN=vxlan0

HOST2_VLAN_IP=1.1.1.1
HOST2_VXLAN_IP=1.1.1.2

HOST2=${HOST2-10.12.205.14}
HOST2_NIC=${HOST2_NIC-enp4s0}
HOST1_IP=${HOST1_IP-192.168.1.13}
HOST2_IP=${HOST2_IP-192.168.1.14}
TIMEOUT=${TIMEOUT:-20}
ROUNDS=${ROUNDS:-2}
VID=${VID-50}
VNI=${VNI-100}
PASSWORD=${PASSWORD:-3tango}


function cleanup() {
    del_all_bridges
    ip netns del ns0 2> /dev/null
    ip netns del ns1 2> /dev/null
}

function config_vf() {
    local ns=$1
    local vf=$2
    local rep=$3
    local ip=$4

    echo "$ns : $vf ($ip) -> $rep"
    if [ ! -e /sys/class/net/$vf ]; then
        err "Cannot find $vf"
        return 1
    fi
    if [ ! -e /sys/class/net/$rep ]; then
        err "Cannot find $rep"
        return 1
    fi
    ifconfig $rep 0 up
    ip netns add $ns
    ip link set $vf netns $ns
    ip netns exec $ns ifconfig $vf $ip/24 up
}

function disable_sriov() {
    title "- Disable SRIOV"
    echo 0 > /sys/class/net/$NIC/device/sriov_numvfs
}

function enable_sriov() {
    title "- Enable SRIOV"
    echo 3 > /sys/class/net/$NIC/device/sriov_numvfs
}

function verify_port_mirror() {
    for i in $(seq $ROUNDS); do
        title "- Enable port mirror"
        ovs-vsctl -- --id=@p get port $REP3 -- --id=@m create mirror name=m0 select-all=true output-port=@p -- set bridge $BR mirrors=@m
        timeout 5 tcpdump ip -nnn -i $VF3
        title "- Disable port mirror"
        ovs-vsctl clear bridge $BR mirrors
        timeout 5 tcpdump ip -nnn -i $VF3
    done
}

function cmd_on()
{
        local host=$1
        shift
        local cmd=$@
        echo "[$host] $cmd"
        sshpass -p $PASSWORD ssh $host -C "$cmd"
}

###################### basic test ##############################

function run_basic_test() {
    ovs-vsctl add-br $BR
    ovs-vsctl add-port $BR $REP1
    ovs-vsctl add-port $BR $REP2
    ovs-vsctl add-port $BR $REP3

    title "Test ping $VF1($NS1_IP) -> $VF2($NS2_IP)"

    ip netns exec ns0 ping -q -c 10 -i 0.2 -w 2 $NS2_IP && success || err "ping failed"
    ip netns exec ns0 ping -q -c $TIMEOUT $NS2_IP &
    verify_port_mirror

    title "Test iperf $VF1($NS1_IP) -> $VF2($NS2_IP)"
    timeout $TIMEOUT ip netns exec ns1 iperf3 -s --one-off -i 0 || err "iperf server failed" &
    sleep 1
    timeout $TIMEOUT ip netns exec ns0 iperf3 -c $NS2_IP -t $((TIMEOUT-2)) -B $NS1_IP -P 100 --cport 6000 -i 0 || err "iperf client failed" &
    verify_port_mirror
}

###################### vlan test ##############################

function config_remote_vlan() {
    [[ $# != 3 ]] && return
    local link=$1 vid=$2 ip=$3 vlan=vlan$VID

    echo "config $HOST2 vlan interface"
    cmd_on $HOST2 ip link del $vlan > /dev/null
    cmd_on $HOST2 modprobe 8021q
    cmd_on $HOST2 ifconfig $link 0
    cmd_on $HOST2 ip link add link $link name $vlan type vlan id $vid
    cmd_on $HOST2 ip link set dev $vlan up
    cmd_on $HOST2 ip addr add $ip/24 brd + dev $vlan
}

function clear_remote_vlan() {
    echo "clear $HOST2 vlan interface"
    cmd_on $HOST2 ip link del vlan$VID > /dev/null
}

function run_vlan_test() {
    title "Start vlan test"

    del_all_bridges
    ovs-vsctl add-br $BR
    ovs-vsctl add-port $BR $NIC
    ovs-vsctl add-port $BR $REP1 tag=$VID
    ovs-vsctl add-port $BR $REP2 tag=$VID
    ovs-vsctl add-port $BR $REP3 tag=$VID

    config_remote_vlan $HOST2_NIC $VID $HOST2_VLAN_IP

    title "Test ping $VF1($NS1_IP) -> remote vlan ($HOST2_VLAN_IP)"

    ip netns exec ns0 ping -q -c $TIMEOUT $HOST2_VLAN_IP &
    verify_port_mirror

    cmd_on $HOST2 pkill iperf
    cmd_on $HOST2 timeout $TIMEOUT iperf3 -s --one-off -i 0 &
    sleep 1
    timeout $TIMEOUT ip netns exec ns0 iperf3 -c $HOST2_VLAN_IP -t $((TIMEOUT-2)) -B $NS1_IP -P 100 --cport 6000 -i 0 &
    verify_port_mirror

    clear_remote_vlan
}

###################### vxlan test ##############################

function config_remote_vxlan() {
    local vxlan_mac=24:25:d0:e2:00:00
    echo "config $HOST2 vxlan interface"
    cmd_on $HOST2 ip link del $HOST2_VXLAN > /dev/null
    cmd_on $HOST2 ifconfig $HOST2_NIC $HOST2_IP
    cmd_on $HOST2 ip link del $HOST2_VXLAN > /dev/null 2>&1
    cmd_on $HOST2 ip link add name $HOST2_VXLAN type vxlan id $VNI dev $HOST2_NIC remote $HOST1_IP dstport 4789
    cmd_on $HOST2 ifconfig $HOST2_VXLAN $HOST2_VXLAN_IP/24 up
    cmd_on $HOST2 ip link set $HOST2_VXLAN address $vxlan_mac
}

function clear_remote_vxlan() {
    echo "clear $HOST2 vxlan interface"
    cmd_on $HOST2 ip link del $HOST2_VXLAN > /dev/null
}

function run_vxlan_test() {
    title "Start vxlan test"

    del_all_bridges
    ovs-vsctl add-br $BR
    ovs-vsctl add-port $BR $REP1
    ovs-vsctl add-port $BR $REP2
    ovs-vsctl add-port $BR $REP3
    ovs-vsctl add-port $BR $HOST1_VXLAN -- set interface $HOST1_VXLAN type=vxlan options:remote_ip=$HOST2_IP  options:key=$VNI

    ifconfig $NIC $HOST1_IP/24 up

    config_remote_vxlan

    title "Test ping $VF1($NS1_IP) -> remote vxlan ($HOST2_VXLAN_IP)"

    ping -q -c 10 -i 0.2 -w 2 $HOST2_IP && success || err "ping failed"
    ip netns exec ns0 ping -q -c $TIMEOUT $HOST2_VXLAN_IP &
    verify_port_mirror

    cmd_on $HOST2 pkill iperf
    cmd_on $HOST2 timeout $TIMEOUT iperf3 -s --one-off -i 0 &
    sleep 1
    timeout $TIMEOUT ip netns exec ns0 iperf3 -c $HOST2_VXLAN_IP -t $((TIMEOUT-2)) -B $NS1_IP -P 100 --cport 6000 -i 0 &
    verify_port_mirror

    clear_remote_vxlan
}

###################### header re-write test ##############################

function config_header_rewrite() {
    ip netns exec ns0 ifconfig $VF1 192.168.0.2/24 up
    ip netns exec ns0 ip route add 8.9.10.0/24 via 192.168.0.1 dev $VF1
    ifconfig $REP1 up

    ip netns exec ns1 ifconfig $VF2 8.9.10.11/24 up
    ifconfig $REP2 up

    del_all_bridges
    ovs-vsctl add-br $BR
    ovs-vsctl add-port $BR $REP1 -- set Interface $REP1 ofport_request=2
    ovs-vsctl add-port $BR $REP2 -- set Interface $REP2 ofport_request=3
    ovs-vsctl add-port $BR $REP3 -- set Interface $REP3 ofport_request=4

    MAC1=$(ip netns exec ns0 cat /sys/class/net/$VF1/address)
    MAC2=$(ip netns exec ns1 cat /sys/class/net/$VF2/address)

    MAC=24:8a:07:ad:77:99

    ovs-ofctl add-flow $BR "table=0, in_port=2, dl_type=0x0806, nw_dst=192.168.0.1, actions=load:0x2->NXM_OF_ARP_OP[], move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], mod_dl_src:${MAC}, move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], load:0x248a07ad7799->NXM_NX_ARP_SHA[], load:0xc0a80001->NXM_OF_ARP_SPA[], in_port"
    ovs-ofctl add-flow $BR "table=0, in_port=2, dl_dst=${MAC}, ip, nw_src=192.168.0.2, nw_dst=8.9.10.11, actions=mod_dl_src=${MAC}, mod_dl_dst=${MAC2}, mod_nw_src=8.9.10.1, output:3"

    ovs-ofctl add-flow $BR "table=0, in_port=3, dl_type=0x0806, nw_dst=8.9.10.1, actions=load:0x2->NXM_OF_ARP_OP[], move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], mod_dl_src:${MAC}, move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], load:0x248a07ad7799->NXM_NX_ARP_SHA[], load:0x08090a01->NXM_OF_ARP_SPA[], in_port"
    ovs-ofctl add-flow $BR "table=0, in_port=3, dl_dst=${MAC}, dl_type=0x0800, nw_dst=8.9.10.1, actions=mod_dl_src=24:8a:07:ad:77:88 mod_dl_dst=${MAC1}, mod_nw_dst=192.168.0.2, output:2"
}

function run_header_rewrite_test() {
    config_header_rewrite

    title "Test ping $VF1(192.168.0.2) -> $VF2 (8.9.10.11)"
    ip netns exec ns0 ping -q -c $TIMEOUT 8.9.10.11 &
    verify_port_mirror

    title "Test iperf $VF1(192.168.0.2) -> $VF2(8.9.10.11)"
    timeout $TIMEOUT ip netns exec ns1 iperf3 -s --one-off -i 0 || err "iperf server failed" &
    sleep 1
    timeout $TIMEOUT ip netns exec ns0 iperf3 -c 8.9.10.11 -t $((TIMEOUT-2)) -B 192.168.0.2 -P 100 --cport 6000 -i 0 || err "iperf client failed" &
    verify_port_mirror
}

###################### main test ##############################

cleanup

disable_sriov
enable_sriov
enable_switchdev $NIC
bind_vfs $NIC

. $my_dir/set-macs.sh $NIC 3

start_clean_openvswitch
config_vf ns0 $VF1 $REP1 $NS1_IP
config_vf ns1 $VF2 $REP2 $NS2_IP
ifconfig $VF3 up
ifconfig $REP3 up
clear_remote_vlan
clear_remote_vxlan

run_basic_test
run_vlan_test
run_vxlan_test
run_header_rewrite_test

wait

cleanup
disable_sriov
test_done
