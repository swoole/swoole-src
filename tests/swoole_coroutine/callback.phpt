--TEST--
swoole_coroutine: coro callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class TestCo
{
    public function foo()
    {
        co::sleep(0.001);
        $cid = go(function () {
            co::yield();
        });
        co::resume($cid);
        echo @$this->test;
    }
}

for ($c = MAX_CONCURRENCY; $c--;) {
    go([new TestCo, 'foo']);
}

?>
--EXPECTF--
