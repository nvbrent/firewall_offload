#
# Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

app_srcs = files([
    'nv_opof_flow.c',
    'nv_opof_globals.c',
    'nv_opof_init.c',
    'nv_opof_log.c',
    'nv_opof_rpc.c',
    'nv_opof_server.c',
    'nv_opof_thread.c',
    'nv_opof_util.c',
])

main_src = files(['nv_opof.c'])

app_dependencies = [
    dependency_libdpdk, 
    grpc_dependencies, 
    dependency_json_rpc,
    dependency_open_offload
]

app_libs = []

app_inc_dirs = [
    '../include', 
]

bin_install_dir = '/usr/sbin'

nv_opof_lib = static_library('nv_opof_lib', app_srcs,
    override_options : [
        'warning_level=2',
        'werror=false'
    ],
    dependencies : app_dependencies,
    include_directories: app_inc_dirs,
    install: false)

nv_opof = executable('nv_opof', main_src,
    override_options : [
        'warning_level=2',
        'werror=false'
    ],
    dependencies : app_dependencies,
    link_with : [app_libs, nv_opof_lib],
    include_directories: app_inc_dirs,
    install_dir : bin_install_dir,
    install: true)

install_data([
    'opof',
    '../scripts/opof_pre_check',
    '../scripts/opof_setup',
    '../scripts/opof_setup_highavail',
    ], install_dir: bin_install_dir)
install_data([
    '../scripts/opof.service', 
    ], install_dir: '/etc/systemd/system')
install_data([
    '../README.md',
    ], install_dir: '/opt/mellanox/nv_opof')
