<?php
function test()
{
    var_dump(func_get_args());
    return "hello world\n";
}
$module = swoole_load_module(__DIR__.'/test.so');

$s = microtime(true);
for($i =0; $i< 1; $i++)
{
    //$ret = swoole_strerror(11);
    $ret = $module->cppMethod("abc", 1234, 459.55, "hello");
}
echo "use ".(microtime(true) - $s)."s\n";
var_dump($ret);

