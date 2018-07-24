#!/bin/sh -e
source ./core.sh
cd ${__DIR__} && \
./docker-compile.sh && \
./docker-test.sh