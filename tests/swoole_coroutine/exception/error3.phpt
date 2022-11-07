--TEST--
swoole_coroutine/exception: internal_function error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
register_shutdown_function(function () {
    echo "shutdown\n";
});
Co\run(function (){
    echo "start\n";

    go('intdiv', 1, 0);

    echo "end\n";
});
echo "done\n";
--EXPECTF--
start

Fatal error: Uncaught DivisionByZeroError:%s:%d
Stack trace:
%A
  thrown in %s on line %d
shutdown
