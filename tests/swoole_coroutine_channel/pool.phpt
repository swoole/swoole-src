--TEST--
swoole_coroutine_channel: connection pool
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (!class_exists("swoole_redis", false))
{
    exit("SKIP");
}
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

/**
 * 连接池尺寸
 */
const POOL_SIZE = 20;
/**
 * 并发协程数量
 */
const CONCURRENCY = 100;
/**
 * 每个协程的执行次数
 */
const COUNT = 100;

class RedisPool
{
    /**
     * @var \Swoole\Coroutine\Channel
     */
    protected $pool;

    /**
     * RedisPool constructor.
     * @param int $size 连接池的尺寸
     */
    function __construct($size = 100)
    {
        $this->pool = new Swoole\Coroutine\Channel($size);
        for ($i = 0; $i < $size; $i++)
        {
            $redis = new Swoole\Coroutine\Redis();
            $res = $redis->connect('127.0.0.1', 6379);
            if ($res == false)
            {
                throw new RuntimeException("failed to connect redis server.");
            }
            else
            {
                $this->put($redis);
            }
        }
    }

    function put($redis)
    {
        $this->pool->push($redis);
    }

    function get()
    {
        return $this->pool->pop();
    }
}

global $count;
$count = 0;

go(function ()
{
    $pool = new RedisPool(POOL_SIZE);
    for ($i = 0; $i < CONCURRENCY; $i++)
    {
        go(function () use ($pool)
        {
            for ($i = 0; $i < COUNT; $i++)
            {
                $redis = $pool->get();
                assert($redis->set("key", "value"));
                $retval = $redis->get("key");
                assert($retval == "value");
                $pool->put($redis);
                global $count;
                $count ++;
            }
        });
    }
});

swoole_event::wait();
assert($count == CONCURRENCY * COUNT);
?>
--EXPECT--