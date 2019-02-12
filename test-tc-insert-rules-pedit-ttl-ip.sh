#!/bin/bash
#
# Test header rewrite on TTL and/or ip addresses changes. For non-TCP/UDP/ICMP
# allowed only TTL change. First test for TCP proto, second - SCTP.
#
# Bug SW #1551898: wrong limitation on IP header re-write
#

SRC_ADDR='7.7.7.1'
DST_ADDR='7.7.7.2'


my_dir="$(dirname "$0")"
. $my_dir/common.sh

not_relevant_for_cx4
not_relevant_for_cx4lx

function tc_filter_success() {
    tc_filter $@ && success
}

function tc_filter_failure() {
    std_error_text="$(tc filter $@ 2>&1)"

    # we expect FAIL exit code from upper command line
    if [[ $? == 0 ]];then
        err "expected command fail"
    elif [[ -z $std_error_text ]];then
        err "expected error message on stderr"
    else
        echo $std_error_text
        std_error_text=${std_error_text%% *}
        if [[ $std_error_text != 'RTNETLINK' ]];then
            warn "expected RTNETLINK error message on stderr"
        else
            success
        fi
    fi
}

function test_tcp_rewrite() {
    title "Test header rewrite for TCP proto"

    title "- ttl field only"
    tc_filter_success add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto tcp \
        action pedit ex \
            munge ip ttl add 0xff \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP

    title "- ttl & addr fields"
    tc_filter_success add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto tcp \
        action pedit ex \
            munge ip ttl add 0xff \
            munge ip src set $SRC_ADDR \
            munge ip dst set $DST_ADDR \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP

    title "- addr fields only"
    tc_filter_success add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto tcp \
        action pedit ex \
            munge ip src set $SRC_ADDR \
            munge ip dst set $DST_ADDR \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP
}

function test_sctp_rewrite() {
    title "Test header rewrite for SCTP proto"

    title "- ttl field only"
    tc_filter_success add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto sctp \
        action pedit ex \
            munge ip ttl add 0xff \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP

    title "- ttl & addr fields (must be RTNETLINK error message)"
    tc_filter_failure add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto sctp \
        action pedit ex \
            munge ip ttl add 0xff \
            munge ip src set $SRC_ADDR \
            munge ip dst set $DST_ADDR \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP

    title "- addr fields only (must be RTNETLINK error message)"
    tc_filter_failure add dev $REP protocol ip parent ffff: prio 1 \
        flower skip_sw ip_proto sctp \
        action pedit ex \
            munge ip src set $SRC_ADDR \
            munge ip dst set $DST_ADDR \
        pipe action mirred egress redirect dev $REP
    reset_tc $REP

}

start_check_syndrome
enable_switchdev
reset_tc $REP

test_tcp_rewrite
test_sctp_rewrite

title "Check log"
check_syndrome
test_done