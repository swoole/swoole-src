--TEST--
swoole_redis: subscribe & publish
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

parent_child(function ($pid)
{
    //父进程
    suicide(3000);
    $redis = new \swoole_redis();
    $redis->on("message", function (\swoole_redis $redis, $message) use ($pid)
    {
        if ($message[0] == 'subscribe')
        {
            return;
        }
        assert($message !== false);
        assert($message[2] === "payload!!!");

        pcntl_waitpid($pid, $status);
        swoole_event_exit();
    });

    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function (\swoole_redis $redis, $r)
    {
        assert($r);
        $redis->subscribe("test_on_message");
    });
}, function ()
{
    //子进程
    suicide(2000);
    $redis = new \swoole_redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function (\swoole_redis $redis, $r)
    {
        assert($r);
        $r = $redis->publish("test_on_message", "payload!!!", function (\swoole_redis $redis, $r)
        {
            assert($r);
            swoole_event_exit();
        });
        assert($r);
    });
});
?>
--EXPECT--
