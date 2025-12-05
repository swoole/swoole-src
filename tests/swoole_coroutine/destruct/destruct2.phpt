--TEST--
swoole_coroutine/destruct: destruct2
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;
class T2
{
    function __construct()
    {

    }
    function test()
    {
        echo "call function\n";
    }

    function __destruct()
    {
        go(function () {
            echo "coro start\n";
            co::sleep(.001);
            echo "coro exit\n";
        });
    }
}

$t = new T2();
$t->test();
echo "end\n";
?>
--EXPECTF--
call function
end

Fatal error: go(): can not use coroutine in __destruct after php_request_shutdown %s
--EXPECTF_85--
call function
end

Fatal error: go(): can not use coroutine in __destruct after php_request_shutdown %s
Stack trace:
#0 %s(%d): go(Object(Closure))
#1 [internal function]: T2->__destruct()
#2 {main}
