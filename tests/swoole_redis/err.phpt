--TEST--
swoole_redis: redis get/set and error return
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$redis = new swoole_redis;
$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function (swoole_redis $redis, $data) {
    var_dump($data);
    $redis->set('foo', 'bar', function (swoole_redis $redis, $data) {
        var_dump($data);
        $redis->hIncrBy('foo', 'bar', 123, function (swoole_redis $redis, $data) {
            var_dump($data);
            var_dump($redis->errCode, $redis->errMsg);
            $redis->set('foo', 'baz', function (swoole_redis $redis, $data) {
                var_dump($data);
                $redis->get('foo', function (swoole_redis $redis, $data) {
                    var_dump($data);
                    $redis->close();
                });
            });
        });
    });
});
?>
--EXPECT--
bool(true)
string(2) "OK"
bool(false)
int(-1)
string(65) "WRONGTYPE Operation against a key holding the wrong kind of value"
string(2) "OK"
string(3) "baz"
