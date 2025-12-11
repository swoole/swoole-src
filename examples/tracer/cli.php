<?php

class ClassA
{
    public $arr;
    public $str;

    public function __construct()
    {
        $this->arr = [];
        $this->str = '';
    }
}

function foo(ClassA $obj)
{
    $str = str_repeat("big string", 1024);
    $obj->arr[] = $str;
    $obj->str .= $str;
}

$obj = new ClassA();
$usage = memory_get_usage();
$n = 100;
while ($n--) {
    foo($obj);
}

var_dump(strlen($obj->str));
var_dump(memory_get_usage() - $usage);
swoole_tracer_leak_detect();
