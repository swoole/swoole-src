#!/bin/bash
cmake .
make -j8
ipcs -q

tasks=$(./bin/core_tests --gtest_list_tests | awk '/\./')
for task in $tasks; do
    if [ $task = "log." ]; then
        ./bin/core_tests --gtest_filter=$task*
    else
        sudo ./bin/core_tests --gtest_filter=$task*
    fi

    if [ $? -ne 0 ] && [ "${GITHUB_ACTIONS}" = true ]; then
        exit 255
    fi
done
