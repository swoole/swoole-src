--TEST--
swoole_process: ctor
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {
    Assert::true(false, 'never here');
});
unset($proc);
echo "SUCCESS";

?>
--EXPECT--
SUCCESS
