--TEST--
swoole_coroutine_util: user suspend and resume4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

go(function () {
    $main = co::getuid();
    echo "start to create coro\n";
    go(function () use ($main) {
        echo "coro 2\n";
        co::sleep(0.1);
        echo "resume\n";
        co::resume($main);
    });
    echo "before suspend \n";
    co::suspend();
    echo "after suspend \n";
});
echo "main \n";

?>
--EXPECTF--
start to create coro
coro 2
before suspend 
main 
resume
after suspend
