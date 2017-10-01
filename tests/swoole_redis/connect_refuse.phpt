--TEST--
swoole_redis: connect refuse

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc";
if (!class_exists("swoole_redis", false))
{
    exit("required redis.");
}
?>

--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$redis = new swoole_redis();

$redis->on("close", function (){
    echo "closed\n";
});

$result = $redis->connect("127.0.0.1", 19009, function ($redis, $result)
{
    assert($redis->errCode == SOCKET_ECONNREFUSED);
    assert($result === false);
});
?>

--EXPECT--
