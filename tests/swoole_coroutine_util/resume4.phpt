--TEST--
swoole_coroutine_util: user yield and resume4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;
co::yield();
$id = go(function(){
    $id = co::getUid();
    echo "start coro $id\n";    
    co::yield();
    echo "resume coro $id\n";
});
echo "start to resume $id\n";
co::resume($id);
echo "main\n";

?>
--EXPECTF--
Fatal error: Swoole\Coroutine::yield(): can not yield outside coroutine %s
