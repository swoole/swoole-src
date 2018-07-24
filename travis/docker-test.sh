#!/bin/sh -e
source ./core.sh
#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/ && \
./start.sh ./swoole_coroutine