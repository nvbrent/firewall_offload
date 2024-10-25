#!/bin/sh -x
# Note this should be possible with "ctr pull $IMAGE" but requires credentials
IMAGE=gitlab-server/firewall_offload:latest
service docker start && \
docker pull $IMAGE && \
docker save $IMAGE | ctr --namespace k8s.io image import -
