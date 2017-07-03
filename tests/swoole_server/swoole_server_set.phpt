--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/6/7
 * Time: 下午4:34
 */
require_once __DIR__ . "/../include/swoole.inc";

$serv = new \swoole_server(TCP_SERVER_HOST, TCP_SERVER_PORT, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
$conf = [
    'dispatch_mode' => 3,
    'worker_num' => 2,
    'a' => 'b',
];
$serv->set($conf);
arrayEqual($conf, $serv->setting);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS