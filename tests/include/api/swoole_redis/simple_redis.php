<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


class Obj
{
}

$redis = new swoole_redis();
$redis->on("close", function ()
{
    echo "close";
});
$redis->on("message", function ()
{
    var_dump(func_get_args());
});

define('REDIS_TEST_KEY', "swoole:test:key_" . md5(microtime()));
define('REDIS_TEST_VALUE', RandStr::gen(128, RandStr::ALPHA | RandStr::NUM | RandStr::CHINESE));

// $swoole_redis->connect(REDIS_SERVER_PATH, false, swoole_function() {}); TODO
$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function (\swoole_redis $redis)
{
    $redis->get(REDIS_TEST_KEY, function (\swoole_redis $redis, $result)
    {
        assert($result === null);
        $redis->set(REDIS_TEST_KEY, REDIS_TEST_VALUE, function (\swoole_redis $redis, $result)
        {
            assert($result === 'OK');
            $redis->get(REDIS_TEST_KEY, function (\swoole_redis $redis, $result)
            {
                assert($result === REDIS_TEST_VALUE);
                $redis->del(REDIS_TEST_KEY, function (\swoole_redis $redis, $result)
                {
                    assert($result === 1);
                    $redis->close();
                });
            });
        });
    });
});
