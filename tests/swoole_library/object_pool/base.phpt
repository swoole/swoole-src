--TEST--
swoole_library/object_pool: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
class R
{
    public function __construct()
    {
        echo "__construct\n";
    }
    
    public function __destruct()
    {
        echo "__destruct\n";
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
});
go(function() use ($pool){
    $object = $pool->get();
});

?>
--EXPECT--
__construct
__destruct
