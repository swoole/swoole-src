--TEST--
swoole_coroutine_scheduler: user yield and resume2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

$map = [];
$id = go(function() use (&$map){
    $id = co::getUid();
    echo "start coro $id\n";
    $id2 = go(function(){
        $id2 = co::getUid();
        echo "start coro $id2\n";
        co::yield();
        echo "resume coro $id2\n";
    });
    $map[2] = $id2;
    co::yield();
    echo "resume coro $id\n";
});
$map[1] = $id;
echo "start to resume {$map[2]}\n";
co::resume($map[2]);
echo "start to resume {$map[1]}\n";
co::resume($map[1]);
echo "main\n";
swoole_event::wait();
?>
--EXPECT--
start coro 1
start coro 2
start to resume 2
resume coro 2
start to resume 1
resume coro 1
main
