--TEST--
swoole_coroutine_system: a new AIO pool picks up settings after the last reactor exits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;

foreach ([1, 2] as $workers) {
    Assert::true(swoole_async_set([
        'aio_core_worker_num' => $workers,
        'aio_worker_num' => $workers,
    ]));
    Coroutine\run(static function () use ($workers) {
        Assert::same(System::readFile(__FILE__), file_get_contents(__FILE__));
        Assert::same(Coroutine::stats()['aio_worker_num'], $workers);
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
