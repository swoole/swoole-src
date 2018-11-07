#!/bin/sh
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

PHP_VERSION_ID=`php -r "echo PHP_VERSION_ID;"`
if [ ${PHP_VERSION_ID} -lt 70300 ]; then
    export PHP_VERSION="`php -r "echo PHP_MAJOR_VERSION;"`.`php -r "echo PHP_MINOR_VERSION;"`"
else
    export PHP_VERSION="rc"
fi
export DOCKER_COMPOSE_VERSION="1.21.0"

install_docker_compose(){
    curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > docker-compose && \
    chmod +x docker-compose && \
    sudo mv docker-compose /usr/local/bin && \
    docker-compose -v && \
    docker -v
}

prepare_files(){
    cd ${__DIR__} && \
    mkdir -p data && \
    mkdir -p data/mysql && \
    mkdir -p data/redis && \
    chmod -R 777 data
}

run_tests_in_docker(){
    docker exec $1 touch /.travisenv && \
    docker exec $1 /swoole-src/.travis/docker-all.sh
}

#------------Only run once-------------
if [ "${TRAVIS_BUILD_DIR}" ]; then
    echo "travis ci with docker...\n"
    set -e
    install_docker_compose && \
    prepare_files && \
    echo "run phpt in docker...\n"
    docker-compose up -d && docker ps && \
    run_tests_in_docker "swoole-alpine" && \
    run_tests_in_docker "swoole"
else
    echo "user tests in docker...\n"
    export TRAVIS_BUILD_DIR=$(cd "$(dirname "$0")";cd ../;pwd)
    prepare_files
fi
