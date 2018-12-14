<?php
use Swoole\Coroutine as co;

$id = go(function(){
    $id = co::getUid();
    echo "start coro $id\n";
    co::suspend($id);
    echo "resume coro $id @1\n";
    co::suspend($id);
    echo "resume coro $id @2\n";
});
echo "start to resume $id @1\n";
co::resume($id);
echo "start to resume $id @2\n";
co::resume($id);
echo "main\n";
