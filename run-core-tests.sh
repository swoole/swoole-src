#!/bin/bash
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

export ASAN_OPTIONS=detect_leaks=0
sudo sysctl -w kernel.randomize_va_space=0

ipcs -q

cd "${__DIR__}"/core-tests/js || exit 1
npm install
cd "${__DIR__}" || exit 1

#
# A test suite which is stuck (for example waiting for an event that never arrives) does not produce
# any output, so the CI job just runs into its own timeout and is cancelled, and the log of the
# hanging suite is lost. Kill such a suite from here instead, and report what it was doing.
#
WATCHDOG_IDLE_SECONDS=${WATCHDOG_IDLE_SECONDS:-300}
SUITE_LOG="${__DIR__}/core-tests-watchdog.log"

# The suite is started with setsid(), so it leads its own process group and the whole tree
# (sudo, the test process and its children) can be terminated at once.
watchdog_kill() {
    sudo kill -TERM -- "-$1" 2>/dev/null || kill -TERM -- "-$1" 2>/dev/null
    sleep 5
    sudo kill -KILL -- "-$1" 2>/dev/null || kill -KILL -- "-$1" 2>/dev/null
}

tasks=$(./bin/core-tests --gtest_list_tests | awk '/\./') || exit 255
for task in $tasks; do
    execute_command="./bin/core-tests"

    : >"${SUITE_LOG}"
    if [ "$task" = "log." ]; then
        setsid stdbuf -oL -eL $execute_command --gtest_filter="$task"* >>"${SUITE_LOG}" 2>&1 &
    else
        setsid sudo -E stdbuf -oL -eL "$execute_command" --gtest_filter="$task"* >>"${SUITE_LOG}" 2>&1 &
    fi
    pid=$!

    idle=0
    last_size=-1
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        size=$(wc -c <"${SUITE_LOG}" 2>/dev/null || echo 0)
        if [ "$size" = "$last_size" ]; then
            idle=$((idle + 1))
        else
            idle=0
            last_size=$size
        fi
        if [ "$idle" -ge "$WATCHDOG_IDLE_SECONDS" ]; then
            echo "watchdog: '${task}' has been silent for ${WATCHDOG_IDLE_SECONDS}s, killing it"
            echo "----- last output of '${task}' -----"
            tail -n 50 "${SUITE_LOG}"
            echo "----- end of the last output -----"
            watchdog_kill "$pid"
            wait "$pid" 2>/dev/null
            exit 255
        fi
    done

    wait "$pid"
    if [ $? -ne 0 ]; then
        tail -n 50 "${SUITE_LOG}"
        exit 255
    fi
done
