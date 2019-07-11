--TEST--
swoole_coroutine/defer: coro defer
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    try {
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
    } catch (Exception $e) {
        echo "catch it\n";
    } finally {
        echo "finally done\n";
    }
});
?>
--EXPECT--
catch it
finally done
closed
