#!/usr/bin/bash

# PREREQUISITES:
# - Setup an ssh key with the DPU Host and External Host
# - Run install_prereqs.sh

source test_conf.sh


# Push source and protos, generate grpc sources, and ensure net devs are up
./remote_setup.sh -r $DPU_HOST -i $DPU_HOST_IFACES
if [[ $? -ne 0 ]]; then
    echo "Failed to set up DPU_HOST $DPU_HOST"
    exit 1
fi
./remote_setup.sh -r $EXT_HOST -i $EXT_HOST_IFACES
if [[ $? -ne 0 ]]; then
    echo "Failed to set up EXT_HOST $EXT_HOST"
    exit 1
fi

#
# Start the traffic-generator daemons:
#
ssh -tt root@$DPU_HOST "cd /tmp/opof_test && python3 opof_test_traffic_gen.py -n DPU_HOST -i $DPU_HOST_IFACES -d $DPU_HOST_DMAC" &
dpu_host_pid=$!

ssh -tt root@$EXT_HOST "cd /tmp/opof_test && python3 opof_test_traffic_gen.py -n EXT_HOST -i $EXT_HOST_IFACES -d $EXT_HOST_DMAC" &
ext_host_pid=$!

# Generate grpc sources for the local test driver:
python3 -m grpc_tools.protoc \
    -I. -I../../subprojects/session_offload/protos/ \
    --python_out=. --pyi_out=. --grpc_python_out=. \
    ./opof_tester.proto \
    ../../subprojects/session_offload/protos/openoffload.proto

# Give daemons time to start
sleep 1

pytest opof_test_driver.py "$@"
#pytest --capture=tee-sys --full-trace opof_test_driver.py "$@"

kill $dpu_host_pid 2> /dev/null
kill $ext_host_pid 2> /dev/null
