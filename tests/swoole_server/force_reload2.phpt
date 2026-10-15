--TEST--
swoole_server: force reload one worker at a time in base mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$mode = SWOOLE_BASE;
require __DIR__ . '/../include/api/swoole_server/force_reload.php';
?>
--EXPECT--
DONE
