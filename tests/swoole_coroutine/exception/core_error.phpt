--TEST--
swoole_coroutine/exception: fatal error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Co\run(function () {
    include TESTS_ROOT_PATH.'/include/api/syntax_error.php';
    sleep(1);
    echo "error\n";
});
echo "end\n";
?>
--EXPECTF--
Parse error: syntax error, unexpected identifier "xde" in %s/syntax_error.php on line 2
end
