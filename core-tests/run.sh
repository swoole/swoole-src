#!/bin/bash
__DIR__=$(cd "$(dirname "$0")";pwd)
__SWOOLE_DIR__=$(cd "$(dirname "${__DIR__}")";pwd)

if [ "${SWOOLE_ENABLE_ASAN}" = 1 ]; then
    cmake . -D swoole_dir="${__SWOOLE_DIR__}" -D enable_thread=1 -D enable_asan=1
else
    cmake . -D swoole_dir="${__SWOOLE_DIR__}" -D enable_thread=1
fi
make -j8
ipcs -q

tasks=$(./bin/core_tests --gtest_list_tests | awk '/\./')
for task in $tasks; do

    if [ "${SWOOLE_VALGRIND}" = 1 ]; then
        # --leak-check=full --show-leak-kinds=all --track-origins=yes
        execute_command="valgrind ./bin/core_tests"
    else
        execute_command="./bin/core_tests"
    fi

    echo "GITHUB_ACTIONS: ${GITHUB_ACTIONS}"

    if [ $task = "log." ]; then
        $execute_command --gtest_filter=$task*
    else
        sudo $execute_command --gtest_filter=$task*
    fi

    if [ $? -ne 0 ] && [ "${GITHUB_ACTIONS}" = true ]; then
        exit 255
    fi
done
