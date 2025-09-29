--TEST--
swoole_thread: map to array
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php

use Swoole\Thread\Map;

require __DIR__ . '/../include/bootstrap.php';

$LURDATE = new Map;
$time = 'abc';
$LURDATE[$time] = new Map(["saaa" => 1111]);
$ls = $LURDATE[$time]->toArray();
foreach ($ls as $k => $v) {
    unset($LURDATE[$time][$k]);
}
unset($LURDATE[$time]);
?>
--EXPECTF--
