#!/bin/sh
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

export DOCKER_COMPOSE_VERSION="v2.33.1"
if [ "${SWOOLE_BRANCH}" = "alpine" ]; then
    export PHP_VERSION="${PHP_VERSION}-alpine"
else
    export PHP_VERSION="${PHP_VERSION}-trixie"
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

create_docker_images(){
  arch=`uname -m`
  if [ "$arch" = "aarch64" ]; then
      echo "\n 📢 create golang-h2demo aarch64 docker image"
      git clone https://github.com/swoole/golang-h2demo.git
      apt install -y golang
      cd ./golang-h2demo && GOOS=linux GOARCH=arm64 go build -o h2demo . && docker build . -t phpswoole/golang-h2demo && cd -

      echo "\n 📢 create ${PHP_VERSION} aarch64 docker image"
      git clone https://github.com/swoole/php-docker.git
      cd php-docker
      cd "${PHP_VERSION%-trixie}" && sed -i '/odbc-mariadb \\/d' Dockerfile && docker build --pull . -t "phpswoole/php:${PHP_VERSION}" && cd - || return 1
      cd ../
  else
      cd "${__DIR__}" && docker-compose pull swoole || return 1
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
    docker exec swoole /swoole-src/scripts/docker-route.sh $SWOOLE_CI_TYPE
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
create_docker_images || exit 1
echo "\n📖 Prepare for files...\n"
prepare_data_files

echo "📦 Start docker containers...\n"
start_docker_containers # && trap "remove_tests_resources"

echo "\n⏳ Run tests in docker...\n"
run_tests_in_docker
echo "\n🚀🚀🚀Completed successfully🚀🚀🚀\n"
