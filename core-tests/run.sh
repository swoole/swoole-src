#!/bin/bash
cmake .
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

    if [ $task = "log." ]; then
        $execute_command --gtest_filter=$task*
    else
        sudo $execute_command --gtest_filter=$task*
    fi

    if [ $? -ne 0 ] && [ "${GITHUB_ACTIONS}" = true ]; then
        exit 255
    fi
done
