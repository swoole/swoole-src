--TEST--
swoole_client_sync: connect 1 - 1

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

/**
 * Time: 上午10:06
 */

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = @$cli->connect("11.11.11.11", 80, 0.5);
echo intval($r);
?>

--EXPECT--
0
