#!/bin/bash
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

cmake . ${CMAKE_ARGS} || exit 1
make VERBOSE=1 -j8  || exit 1
ipcs -q

cd "${__DIR__}"/core-tests/js || exit 1
npm install
cd "${__DIR__}" || exit 1

tasks=$(./bin/core-tests --gtest_list_tests | awk '/\./') || exit 255
for task in $tasks; do
    execute_command="./bin/core-tests"

    echo "run tests for $task"

    if [ "$task" = "log." ]; then
        $execute_command --gtest_filter="$task"*
    else
        sudo -E "$execute_command" --gtest_filter="$task"*
    fi

    if [ $? -ne 0 ] && [ "${GITHUB_ACTIONS}" = true ]; then
        exit 255
    fi
done
