<?php
// require  __DIR__ . "/coro_include.php";
use Swoole\Coroutine as co;
co::create(function () {
    echo "start\n";
    co::sleep(0.5);
    echo "OK\n";
});
echo "11\n";
