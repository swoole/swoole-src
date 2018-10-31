#!/bin/sh
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

prepare(){
    cd ${__DIR__} && \
    mkdir -p data && \
    mkdir -p data/mysql && \
    mkdir -p data/redis && \
    chmod -R 777 data
}

#------------Only run once-------------
if [ "${TRAVIS_BUILD_DIR}" ]; then
    php_version=`php -r "echo PHP_VERSION_ID;"`
    if [ ${php_version} -lt 70400 ]; then
        export PHP_VERSION="`php -r "echo PHP_MAJOR_VERSION;"`.`php -r "echo PHP_MINOR_VERSION;"`"
        echo "travis ci with docker...\n"
        set -e
        DOCKER_COMPOSE_VERSION="1.21.0"
        curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > docker-compose && \
        chmod +x docker-compose && \
        sudo mv docker-compose /usr/local/bin && \
        docker-compose -v && \
        docker -v && \
        prepare && \
        echo "run phpt in docker...\n" && \
        docker-compose up -d && \
        docker ps && \
        docker exec swoole-alpine touch /.travisenv && \
        docker exec swoole-alpine /swoole-src/travis/docker-all.sh && \
        docker exec swoole touch /.travisenv && \
        docker exec swoole /swoole-src/travis/docker-all.sh
    else
        echo "skip php nightly\n"
    fi
else
    echo "user tests in docker...\n"
    export TRAVIS_BUILD_DIR=$(cd "$(dirname "$0")";cd ../;pwd)
    prepare
fi
