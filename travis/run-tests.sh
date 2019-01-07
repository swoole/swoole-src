#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/

# initialization
echo "\n⭐️ Initialization for tests...\n"
./init
echo "\n"

# debug
for debug_file in ${__DIR__}/debug/*.php
do
    if test -f "${debug_file}";then
        debug_file_basename="`basename ${debug_file}`"
        echo "\n====== RUN ${debug_file_basename} ======\n"
        php "${debug_file}"
        echo "\n========================================\n"
    fi
done

# run tests @params($1=list_file, $1=options)
run_tests()
{
    ./start.sh \
    "`tr '\n' ' ' < ${1} | xargs`" \
    -w ${1} \
    ${2}
}

touch tests.list
trap "rm -f tests.list; echo ''; echo '⌛ Done on '`date "+%Y-%m-%d %H:%M:%S"`;" EXIT

if [ "`git symbolic-ref --short -q HEAD`"x == "valgrind"x ]; then
    dir="base"
    options="-m"
else
    dir="swoole_*"
    options=""
fi
echo "${dir}" > tests.list
for i in 1 2 3 4 5
do
    if [ "`cat tests.list`" ]; then
        if [ ${i} -gt "1" ]; then
            sleep ${i}
            echo "\n😮 Retry failed tests#${i}:\n"
        fi
        cat tests.list
        timeout=`echo | expr ${i} \* 10`
        options="${options} --set-timeout ${timeout}"
        run_tests tests.list "${options}"
    else
        break
    fi
done
if [ "`cat tests.list`" ]; then
    exit 255
fi
