--TEST--
swoole_channel_coro: lock
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class CoLock
{
    private $chan;

    function __construct()
    {
        $chan = new chan(1);
        $chan->push(true);
        $this->chan = $chan;
    }

    function lock()
    {
        return $this->chan->pop();
    }

    function unlock()
    {
        return $this->chan->push(true);
    }
}

class Test
{
    static $num = 2;

    static function process(CoLock $lock)
    {
        co::sleep(0.001);
        //这里需要操作全局对象，有可能会有上下文的问题
        //使用 chan 实现协程锁
        $lock->lock();
        if (Test::$num > 0) {
            co::sleep(0.02);
            Test::$num--;
            $lock->unlock();
        } else {
            $lock->unlock();
            echo "fail\n";
        }
    }
}

go(function () {
    $lock = new CoLock;
    $n = 3;
    while ($n--) {
        go('Test::process', $lock);
    }
});

swoole_event::wait();
?>
--EXPECT--
fail
