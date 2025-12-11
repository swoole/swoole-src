<?php

const N = 200;


class testA
{
    public $pro;
}
function foo()
{
    var_dump(memory_get_usage());
    for ($i = 0; $i < N; $i++) {
        $obj = new testA();
        $obj->pro = $obj;
        unset($obj);

        swoole_tracer_leak_detect(64);
    }
    var_dump(memory_get_usage());
}
foo();
