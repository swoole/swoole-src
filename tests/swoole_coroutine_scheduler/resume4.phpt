--TEST--
swoole_coroutine_scheduler: user yield and resume4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::yield();
$id = go(function () {
    $id = Co::getUid();
    echo "start coro $id\n";
    Co::yield();
    echo "resume coro $id\n";
});
echo "start to resume $id\n";
Co::resume($id);
echo "main\n";
swoole_event::wait();
?>
--EXPECTF--
[%s]	ERROR	(PHP Fatal Error: 10001):
Swoole\Coroutine::yield: API must be called in the coroutine
Stack trace:
#0  Swoole\Coroutine::yield() called at [%s:%d]
