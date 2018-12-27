#!/bin/sh -e
__CURRENT__=`pwd`
__DIR__=$(cd "$(dirname "$0")";pwd)

#-------------PHPT-------------
cd ${__DIR__} && cd ../tests/

# initialization
echo "\n⭐️ Initialization for tests...\n"
php ./init
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

# run tests @params($1=list_file, $2=timeout)
run_tests()
{
    ./start.sh \
    --set-timeout ${2} \
    --show-slow 1000 \
    --show-diff \
    -w ${1} \
    "`tr '\n' ' ' < ${1}`"
}

for dir in "swoole_*"
do
    echo "${dir}" > tests.list
    for i in 1 2 3 4 5
    do
        if [ "`cat tests.list`" ]; then
            if [ ${i} -gt "1" ]; then
                sleep ${i}
                echo "\n😮 Retry failed tests#${i}:\n"
            fi
            cat tests.list
            run_tests tests.list "`echo | expr ${i} \* 10`"
        else
            break
        fi
    done
    if [ "`cat tests.list`" ]; then
        exit 255
    fi
done
