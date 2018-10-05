--TEST--
swoole_coroutine_channel: connection pool
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_async_redis();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
    public function __construct($size = 100)
    {
        $this->pool = new Swoole\Coroutine\Channel($size);
        for ($i = 0; $i < $size; $i++) {
            $redis = new Swoole\Coroutine\Redis();
            $res = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
            if ($res == false) {
                throw new RuntimeException("failed to connect redis server.");
            } else {
                $this->put($redis);
            }
        }
    }

    public function put(Swoole\Coroutine\Redis $redis)
    {
        $this->pool->push($redis);
    }

    public function get(): Swoole\Coroutine\Redis
    {
        return $this->pool->pop();
    }
}

$count = 0;
go(function () use (&$count) {
    $pool = new RedisPool(POOL_SIZE);
    for ($i = 0; $i < CONCURRENCY; $i++) {
        go(function () use ($pool) {
            for ($i = 0; $i < COUNT; $i++) {
                $redis = $pool->get();
                assert($redis->set("key", "value"));
                $retval = $redis->get("key");
                assert($retval == "value");
                $pool->put($redis);
                global $count;
                $count++;
            }
        });
    }
});

swoole_event::wait();
assert($count == CONCURRENCY * COUNT);
?>
--EXPECT--