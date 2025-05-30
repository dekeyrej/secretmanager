#!/usr/bin/env bash
export repository=ghcr.io/dekeyrej
export tag=latest
export BUILDX_BUILDER=container

docker buildx build --platform linux/amd64,linux/arm64 --tag ${repository}/recryptonator-image:${tag} --push .