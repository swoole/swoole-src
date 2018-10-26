--TEST--
swoole_redis: connect refuse

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
