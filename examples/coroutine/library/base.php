<?php
class RedisPool extends \Swoole\Coroutine\ObjectPool
{
    public function __construct()
    {
        parent::__construct(__CLASS__);
    }
    
    public function create()
    {
        $cid = \Swoole\Coroutine::getCid();
        echo "cid:$cid create redis\n";
        $redis = new Redis;
        $retval = $redis->connect("127.0.0.1", 6379);
        return $redis;
    }
}
$pool = new RedisPool();
go(function() use ($pool){
    $object = $pool->get();
    var_dump($object);
    var_dump($pool);
    $pool->free();
});
go(function() use ($pool){
    $object = $pool->get();
    var_dump($object);
    $pool->free();
});
    
