#!/bin/bash

[ -z "${TRAVIS_BRANCH}" ] && export TRAVIS_BRANCH="master"
[ -z "${TRAVIS_BUILD_DIR}" ] && export TRAVIS_BUILD_DIR=$(cd "$(dirname "$0")";cd ../;pwd)
export DOCKER_COMPOSE_VERSION="1.21.0"
export PHP_VERSION_ID=`php -r "echo PHP_VERSION_ID;"`
if [ ${PHP_VERSION_ID} -lt 70300 ]; then
    export PHP_VERSION="`php -r "echo PHP_MAJOR_VERSION;"`.`php -r "echo PHP_MINOR_VERSION;"`"
else
    export PHP_VERSION="rc"
fi
if [ "${TRAVIS_BRANCH}" = "alpine" ]; then
    export PHP_VERSION="${PHP_VERSION}-alpine"
fi
