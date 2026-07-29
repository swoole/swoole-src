--TEST--
swoole_coroutine/destruct: yield while destroying a child coroutine after its parent exits
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;

class YieldInDestructor
{
    public function __destruct()
    {
        echo "child destructor start\n";
        Coroutine::sleep(0.001);
        echo "child destructor end\n";
    }
}

go(function () {
    go(function () {
        Coroutine::getContext()->value = new YieldInDestructor;
    });
    echo "parent end\n";
});

Swoole\Event::wait();

echo "done\n";
?>
--EXPECT--
child destructor start
parent end
child destructor end
done
