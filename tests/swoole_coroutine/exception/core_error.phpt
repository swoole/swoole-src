--TEST--
swoole_coroutine/exception: fatal error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
register_shutdown_function(function (){
    echo "shutdown\n";
});
Co\run(function () {
    include TESTS_ROOT_PATH.'/include/api/syntax_error.txt';
    sleep(1);
    echo "error\n";
});
echo "end\n";
?>
--EXPECTF--
Parse error: syntax error, unexpected identifier "xde" in %s on line %d
shutdown
