<?php

function test3($a, $b)
{
    usleep(random_int(100, 500) * 1000);
    return ($a + 3) * ($b + 3);
}


function test2()
{
    usleep(random_int(100, 500) * 1000);
    $res = test3(3, 5);
    print($res . "\n");
}


function main()
{
    var_dump(__FUNCTION__);
    test2();
    $o = new T;
    $o->method_test();
    call_user_func('test4');
}

function test4()
{
    usleep(random_int(100, 500) * 1000);
    var_dump(time());
}

class T
{
    function method_test()
    {
        usleep(random_int(100, 500) * 1000);
        var_dump(__METHOD__);
    }
}

swoole_tracer_prof_begin(['root_path' => __DIR__]);
main();
var_dump(swoole_tracer_prof_end('./test.json'));