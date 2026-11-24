#!/bin/bash
__DIR__=$(cd "$(dirname "$0")" || exit;pwd)

export ASAN_OPTIONS=detect_leaks=0
# Some sudo implementations ignore -E. Pass the settings consumed by the tests
# explicitly so privileged suites still recognize CI and retain their diagnostics.
test_env=()
for name in ASAN_OPTIONS DISPLAY_BACKTRACE GITHUB_ACTIONS SSL_CERT_FILE VERBOSE; do
    if [[ ${!name+x} ]]; then
        test_env+=("$name=${!name}")
    fi
done

sudo sysctl -w kernel.randomize_va_space=0

ipcs -q

cd "${__DIR__}"/core-tests/js || exit 1
npm install || exit 1
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

if ! test_list=$(./bin/core-tests --gtest_list_tests); then
    printf '%s\n' "$test_list" >&2
    echo "Failed to list core tests" >&2
    exit 255
fi
# Only unindented GoogleTest suite names belong here, not diagnostics or individual test names.
mapfile -t tasks < <(printf '%s\n' "$test_list" | awk '/^[^[:space:]]/ && $1 ~ /^[[:alnum:]_\/]+\.$/ { print $1 }')
if [ "${#tasks[@]}" -eq 0 ]; then
    printf '%s\n' "$test_list" >&2
    echo "No core test suites found" >&2
    exit 255
fi
printf 'Discovered %d core test suites\n' "${#tasks[@]}"
for task in "${tasks[@]}"; do
    execute_command="./bin/core-tests"

    printf 'Running core test suite: %s\n' "$task"
    : >"${SUITE_LOG}"
    if [ "$task" = "log." ]; then
        setsid stdbuf -oL -eL "$execute_command" --gtest_color=no --gtest_filter="${task}*" >>"${SUITE_LOG}" 2>&1 &
    else
        setsid sudo -E env "${test_env[@]}" stdbuf -oL -eL "$execute_command" --gtest_color=no --gtest_filter="${task}*" >>"${SUITE_LOG}" 2>&1 &
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
        # The failing test may be followed by many successful tests. Keep its
        # assertions and diagnostics instead of printing only the suite's tail.
        cat "${SUITE_LOG}"
        exit 255
    fi
    # A successful exit alone does not prove that the filter selected any tests.
    if ! grep -Eq '^\[==========\] [1-9][0-9]* tests? from .* ran\.' "${SUITE_LOG}"; then
        cat "${SUITE_LOG}"
        echo "No core tests executed for '${task}'" >&2
        exit 255
    fi
    # Show GoogleTest progress for successful suites; keep verbose engine traces in the watchdog log.
    grep -E '^\[(=|-| RUN |[[:space:]]+(OK|PASSED|SKIPPED))' "${SUITE_LOG}"
done
