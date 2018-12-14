--TEST--
swoole_process: ctor
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {
    assert(false);
});
unset($proc);
echo "SUCCESS";

?>
--EXPECT--
SUCCESS