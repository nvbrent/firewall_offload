#!/bin/bash

#
# Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

DOCA_SERVICE=nv_opof
DOCA_SERVICE_DIR=/opt/mellanox/doca/services/$DOCA_SERVICE

# Stop the service when the container stops
function quit() {
    kill "${pid}"
    # Giving some time to finish program cleanup before calling exit
    timeout 10 tail --pid="${pid}" -f /dev/null
    exit 0
}
trap quit SIGTERM

PATH=$DOCA_SERVICE_DIR:$PATH
PS1=($DOCA_SERVICE) $PS1

# Start the DOCA Service
opof_setup && $DOCA_SERVICE $EAL_FLAGS -- $APP_ARGS &

pid="${!}"

# Run until the service stops
wait "${pid}"
