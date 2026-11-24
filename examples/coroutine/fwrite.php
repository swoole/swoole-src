<?php
// This example writes a temporary file; remove it on exit to keep the tree clean.
register_shutdown_function(function () {
    foreach (glob(__DIR__ . '/test.data') as $file) {
        @unlink($file);
    }
});
use Swoole\Coroutine as co;

$fp = fopen(__DIR__ . "/test.data", "a+");

co::create(function () use ($fp)
{
    $r =  co::fwrite($fp, "hello world\n", 5);
    var_dump($r);
});
