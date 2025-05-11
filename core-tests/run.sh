#!/bin/bash
__DIR__=$(cd "$(dirname "$0")";pwd)
__SWOOLE_DIR__=$(cd "$(dirname "${__DIR__}")";pwd)
CMAKE_ARGS="-D swoole_dir=${__SWOOLE_DIR__} -D enable_thread=1"

if [ "${SWOOLE_ENABLE_ASAN}" = 1 ]; then
    CMAKE_ARGS="${CMAKE_ARGS} -D enable_asan=1"
fi

if [ "${SWOOLE_ENABLE_VERBOSE}" = 1 ]; then
    CMAKE_ARGS="${CMAKE_ARGS} -D enable_verbose=1"
fi

cmake . ${CMAKE_ARGS}
make -j8
ipcs -q

cd ${__DIR__}/js
npm install
cd ${__DIR__}

tasks=$(./bin/core_tests --gtest_list_tests | awk '/\./')
for task in $tasks; do

    if [ "${SWOOLE_VALGRIND}" = 1 ]; then
        # --leak-check=full --show-leak-kinds=all --track-origins=yes
        execute_command="valgrind ./bin/core_tests"
    elif [ "${SWOOLE_ENABLE_STRACE}" = 1 ]; then
        execute_command="strace -f ./bin/core_tests"
    else
        execute_command="./bin/core_tests"
    fi

    echo "run tests for $task"

    if [ $task = "log." ]; then
        $execute_command --gtest_filter=$task*
    else
        sudo -E $execute_command --gtest_filter=$task*
    fi

    if [ $? -ne 0 ] && [ "${GITHUB_ACTIONS}" = true ]; then
        exit 255
    fi
done
