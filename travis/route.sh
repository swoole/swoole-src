#!/bin/sh
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#------------ ENV -------------
PHP_VERSION_ID=`php -r "echo PHP_VERSION_ID;"`
if [ ${PHP_VERSION_ID} -lt 70300 ]; then
    export PHP_VERSION="`php -r "echo PHP_MAJOR_VERSION;"`.`php -r "echo PHP_MINOR_VERSION;"`"
else
    export PHP_VERSION="rc"
fi
export DOCKER_COMPOSE_VERSION="1.21.0"

#------------ FUNCTIONS -------------
install_docker_compose(){
    which "docker-compose" > /dev/null
    if [ $? -ne 0 ]; then
        echo "\nCan no found docker-compose, try to install it now...\n"
        curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > docker-compose && \
        chmod +x docker-compose && \
        sudo mv docker-compose /usr/local/bin && \
        docker -v && \
        docker-compose -v
    fi
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
    docker exec $1 /swoole-src/travis/docker-all.sh
}

#------------ RUN TESTS -------------
install_docker_compose

if [ "${TRAVIS_BUILD_DIR}"x = ""x ]; then
    export TRAVIS_BUILD_DIR=$(cd "$(dirname "$0")";cd ../;pwd)
fi

set -e

echo "\nPrepare for files...\n"
prepare_files

echo "\nStart docker containers...\n"
docker-compose up -d && docker ps

echo "\nRun tests in docker...\n"
run_tests_in_docker "swoole-alpine"
run_tests_in_docker "swoole"
