--TEST--
swoole_coroutine: __destruct coroutine
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
use Swoole\Coroutine as co;
class T
{
    function __construct()
    {
      
    }

    function test()
    {
        echo "call function \n";
    }

    function __destruct()
    {    
        go(function () {
            echo "coro start\n";
            co::sleep(1.0);       
            echo "coro exit\n";
        });
    }
}

$t = new T();
$t->test();
unset($t);
?>
--EXPECT--
call function 
coro start
coro exit