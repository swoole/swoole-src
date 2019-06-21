--TEST--
swoole_library/object_pool: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
class Pool extends \Swoole\Coroutine\ObjectPool
{
    public function __construct($type)
    {
        parent::__construct($type);
    }

    public function create()
    {
        $cid = \Swoole\Coroutine::getCid();
        echo "create\n";
        return new \stdClass();
    }
}
$pool = new Pool("test");
go(function() use ($pool){
    $object = $pool->get();
    $pool->free();
});
go(function() use ($pool){
    $object = $pool->get();
    $pool->free();
});

?>
--EXPECT--
create
