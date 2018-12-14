--TEST--
swoole_coroutine_util: user yield and resume4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
    echo "before yield\n";
    co::yield();
    echo "after yield\n";
});
echo "main\n";

?>
--EXPECTF--
start to create coro
coro 2
before yield
main
resume
after yield
