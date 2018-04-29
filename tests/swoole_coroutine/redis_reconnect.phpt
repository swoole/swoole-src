--TEST--
swoole_coroutine: redis reconnect
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $res = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($res);
    $redis->close();
    $res2 = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($res2);
});
?>
--EXPECT--

