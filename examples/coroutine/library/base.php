<?php
class R
{
    public function __construct()
    {
        $cid = \Swoole\Coroutine::getCid();
        echo "cid:$cid ".__CLASS__ . '#' . \spl_object_id((object)$this) . ' constructed' . PHP_EOL;
    }
    
    public function __destruct()
    {
        $cid = \Swoole\Coroutine::getCid();
        echo "cid:$cid ".__CLASS__ . '#' . \spl_object_id((object)$this) . ' destructed' . PHP_EOL;
    }
}

class Pool extends \Swoole\Coroutine\ObjectPool
{
    public function __construct($type)
    {
        parent::__construct($type);
    }
    
    public function create()
    {
        return new R;
    }
}

$pool = new Pool("test");
go(function() use ($pool){
    $object = $pool->get();
    $cid = \Swoole\Coroutine::getCid();
    echo "cid:$cid ".var_export($object,1)."\n";
});
go(function() use ($pool){
    $object = $pool->get();
    $cid = \Swoole\Coroutine::getCid();
    echo "cid:$cid ".var_export($object,1)."\n";
});
