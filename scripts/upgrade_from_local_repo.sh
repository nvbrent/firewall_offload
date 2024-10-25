#!/bin/sh -x
if [ "${PWD##*/}" = 'scripts' ]; then
    cd ..; 
fi
IMAGE=gitlab-server/firewall_offload:latest
service docker start && \
docker build -f scripts/Dockerfile.opof . -t $IMAGE &&\
docker save $IMAGE | ctr --namespace k8s.io image import -

