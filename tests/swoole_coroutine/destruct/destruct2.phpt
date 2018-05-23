--TEST--
swoole_coroutine: destruct2
--SKIPIF--
<?php require  __DIR__ . "/../../include/skipif.inc"; ?>
--FILE--
<?php
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
echo "end\n";
?>
--EXPECTF--
call function 
end

Fatal error: go(): can not use coroutine in __destruct after php_request_shutdown %s
