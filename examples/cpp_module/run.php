<?php
function test()
{
    var_dump(func_get_args());
}
$module = swoole_load_module(__DIR__.'/test.so');
$ret = $module->cppMethod("abc", 1234, 459.55, "hello");
var_dump($ret);