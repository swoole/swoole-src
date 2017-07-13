--TEST--
swoole_client sync: connect 1 - 3 nonblocking connect & select

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
/**

 * Time: 上午10:06
 */
require_once __DIR__ . "/../include/swoole.inc";

killself_in_syncmode(1000, SIGTERM);


$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = $cli->connect(IP_BAIDU, 80, 1);
assert($r);
$r = $w = $e = [$cli];
$n = swoole_client_select($r, $w, $e, 0);
assert($n === 1);
assert(count($w) === 1);
assert(count($e) === 0);
assert(count($r) === 0);
$cli->close();
echo "SUCCESS";
?>

--EXPECT--
SUCCESS
