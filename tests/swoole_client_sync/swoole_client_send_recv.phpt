--TEST--
swoole_client sync: send & recv

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

killself_in_syncmode(1000);


$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$r = $cli->connect(IP_BAIDU, 80);
assert($r);
$r = $cli->send("GET / HTTP/1.1\r\n\r\n");
assert($r === 18);
$r = $cli->recv();
assert($r !== false);
assert(substr($r, 0, 4) === "HTTP");
echo "SUCCESS";

?>

--EXPECT--
SUCCESS
