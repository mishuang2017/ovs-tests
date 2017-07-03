#!/bin/bash
#
# Test max rules in skip_sw and skip_hw on single port.
# Test max rules in 2 ports.
#
# Bug SW #900706: Adding 42K flows results in a fw error

NIC=${1:-ens5f0}
NIC2=${2:-ens5f1}

my_dir="$(dirname "$0")"
. $my_dir/common.sh

set -e

for nic in $NIC $NIC2; do
	# in case user has only one NIC
	if [[ "$nic" == "NULL" ]]; then
		continue
	fi
	for num in 8*1024 30*1024 64*1024; do
		for skip in skip_hw skip_sw; do
			for index in 0 1; do
				title "Testing $num $skip $nic $index"
				sh $my_dir/tc_batch.sh $num $skip $NIC $index \
				    && success || fail
			done
		done
	done
done

test_done
