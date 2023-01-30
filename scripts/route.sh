#!/bin/sh
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

export DOCKER_COMPOSE_VERSION="1.21.0"
[ -z "${SWOOLE_BRANCH}" ] && export SWOOLE_BRANCH="master"
[ -z "${SWOOLE_BUILD_DIR}" ] && export SWOOLE_BUILD_DIR=$(cd "$(dirname "$0")";cd ../;pwd)
[ -z "${PHP_VERSION_ID}" ] && export PHP_VERSION_ID=`php -r "echo PHP_VERSION_ID;"`
if [ ${PHP_VERSION_ID} -lt 80300 ]; then
    export PHP_VERSION="`php -r "echo PHP_MAJOR_VERSION;"`.`php -r "echo PHP_MINOR_VERSION;"`"
else
    export PHP_VERSION="rc"
fi
if [ "${SWOOLE_BRANCH}" = "alpine" ]; then
    export PHP_VERSION="${PHP_VERSION}-alpine"
fi

echo "\n🗻 With PHP version ${PHP_VERSION} on ${SWOOLE_BRANCH} branch"

check_docker_dependency(){
    if [ "`docker -v 2>&1 | grep "version"`"x = ""x ]; then
        echo "\n❌ Docker not found!"
        exit 1
    elif [ "`docker ps 2>&1 | grep Cannot`"x != ""x ]; then
        echo "\n❌ Docker is not running!"
        exit 1
    else
        which "docker-compose" > /dev/null
        if [ $? -ne 0 ]; then
            echo "\n🤔 Can not found docker-compose, try to install it now...\n"
            curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > docker-compose && \
            chmod +x docker-compose && \
            sudo mv docker-compose /usr/local/bin

            which "docker-compose" > /dev/null
            if [ $? -ne 0 ]; then
                echo "\n❌ Install docker-compose failed!"
                exit 1
            fi

            docker -v &&  docker-compose -v
        fi
    fi
}

prepare_data_files(){
    cd ${__DIR__} && \
    remove_data_files && \
    mkdir -p \
    data \
    data/run \
    data/mysql data/run/mysqld \
    data/redis data/run/redis && \
    chmod -R 777 data
    if [ $? -ne 0 ]; then
        echo "\n❌ Prepare data files failed!"
        exit 1
    fi
}

remove_data_files(){
    cd ${__DIR__} && \
    rm -rf scripts/data
}

start_docker_containers(){
    remove_docker_containers
    cd ${__DIR__} && \
    docker-compose up -d && \
    docker ps -a
    if [ $? -ne 0 ]; then
        echo "\n❌ Create containers failed!"
        exit 1
    fi
}

remove_docker_containers(){
    cd ${__DIR__} && \
    docker-compose kill > /dev/null 2>&1 && \
    docker-compose rm -f > /dev/null 2>&1
}

run_tests_in_docker(){
    docker exec swoole touch /.cienv && \
    docker exec swoole /swoole-src/scripts/docker-route.sh
    code=$?
    if [ $code -ne 0 ]; then
        echo "\n❌ Run tests failed! ExitCode: $code"
        exit 1
    fi
}

remove_tests_resources(){
    remove_docker_containers
    remove_data_files
}

check_docker_dependency

echo "\n📖 Prepare for files...\n"
prepare_data_files

echo "📦 Start docker containers...\n"
start_docker_containers # && trap "remove_tests_resources"

echo "\n⏳ Run tests in docker...\n"
run_tests_in_docker

echo "\n🚀🚀🚀Completed successfully🚀🚀🚀\n"
