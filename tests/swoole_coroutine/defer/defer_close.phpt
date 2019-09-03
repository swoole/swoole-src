--TEST--
swoole_coroutine/defer: coro defer
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $obj = new class
    {
        public $resource;

        public function close()
        {
            $this->resource = null;
        }
    };
    defer(function () use ($obj) {
        $obj->close();
    });
    $obj->resource = $file = fopen(__FILE__, 'r+');
    defer(function () use ($obj) {
        Assert::assert(is_resource($obj->resource));
        fclose($obj->resource);
        echo "closed\n";
    });
    throw new Exception('something wrong');
    echo "never here\n";
});
swoole_event_wait();
?>
--EXPECTF--
closed

Fatal error: Uncaught Exception: something wrong in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
