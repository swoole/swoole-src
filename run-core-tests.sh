#!/bin/bash
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

export ASAN_OPTIONS=detect_leaks=0
echo 0 > /proc/sys/kernel/randomize_va_space

ipcs -q

cd "${__DIR__}"/core-tests/js || exit 1
npm install
cd "${__DIR__}" || exit 1

tasks=$(./bin/core-tests --gtest_list_tests | awk '/\./') || exit 255
for task in $tasks; do
    execute_command="./bin/core-tests"

    if [ "$task" = "log." ]; then
        $execute_command --gtest_filter="$task"*
    else
        sudo -E "$execute_command" --gtest_filter="$task"*
    fi

    if [ $? -ne 0 ]; then
        exit 255
    fi
done
