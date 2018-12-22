--TEST--
swoole_process: setaffinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$r = \swoole_process::setaffinity([0]);
assert($r);

$r = \swoole_process::setaffinity([0, 1]);
assert($r);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS