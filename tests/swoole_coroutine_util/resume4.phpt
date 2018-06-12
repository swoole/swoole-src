--TEST--
swoole_coroutine: user suspend and resume4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/swoole.inc';

use Swoole\Coroutine as co;
co::suspend();
$id = go(function(){
    $id = co::getUid();
    echo "start coro $id\n";    
    co::suspend();
    echo "resume coro $id\n";
});
echo "start to resume $id\n";
co::resume($id);
echo "main\n";

?>
--EXPECTF--
Fatal error: Swoole\Coroutine::suspend(): can not suspend outside coroutine %s
