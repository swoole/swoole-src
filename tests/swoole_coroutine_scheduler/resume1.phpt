--TEST--
swoole_coroutine_scheduler: user yield and resume1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

$id = go(function(){
    $id = co::getUid();
    echo "start coro $id\n";
    co::yield();
    echo "resume coro $id @1\n";
    co::yield();
    echo "resume coro $id @2\n";
});
echo "start to resume $id @1\n";
co::resume($id);
echo "start to resume $id @2\n";
co::resume($id);
echo "main\n";
swoole_event::wait();
?>
--EXPECT--
start coro 1
start to resume 1 @1
resume coro 1 @1
start to resume 1 @2
resume coro 1 @2
main
