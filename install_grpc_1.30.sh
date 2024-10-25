#!/usr/bin/sh

ROOT_DIR=`pwd -P`

GRPC_REPO_DIR=${ROOT_DIR}/subprojects/grpc
GRPC_BUILD_DIR=${GRPC_REPO_DIR}/cmake/_build
GRPC_INSTALL_DIR=/opt/mellanox/grpc-1.30.0
GRPC_TARBALL=grpc-1.30.0.tgz

git clone --recurse-submodules -b v1.30.0 https://github.com/grpc/grpc ${GRPC_REPO_DIR} && \
cd ${GRPC_REPO_DIR} && \
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX="$GRPC_INSTALL_DIR" -S. -B${GRPC_BUILD_DIR} -GNinja && \
ninja -C ${GRPC_BUILD_DIR} install
cd -
tar -czvf ${GRPC_TARBALL} ${GRPC_INSTALL_DIR}

echo Please set the following shell variables:
echo export PATH=${GRPC_INSTALL_DIR}/bin:\$PATH
echo export PKG_CONFIG_PATH=${GRPC_INSTALL_DIR}/lib/pkgconfig:\$PKG_CONFIG_PATH
