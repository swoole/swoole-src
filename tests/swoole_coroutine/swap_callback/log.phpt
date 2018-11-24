--TEST--
swoole_coroutine: coro swap callback
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
co::onSwap(function (int $state, int $cid, int $origin_cid) {
    $cid1 = $cid2 = -1;
    switch ($state){
        case SWOOLE_CORO_INIT:
            $state = 'create';
            $cid1 = $origin_cid;
            $cid2 = $cid;
            break;
        case SWOOLE_CORO_WATING:
            $state = 'yield';
            $cid1 = $cid;
            $cid2 = $origin_cid;
            break;
        case SWOOLE_CORO_RUNNING:
            $state = 'resume';
            $cid1 = $origin_cid;
            $cid2 = $cid;
            break;
        case SWOOLE_CORO_END:
            $state = 'close';
            $cid1 = $cid;
            $cid2 = $origin_cid;
            break;
    }
    echo "from={$cid1} {$state} to={$cid2}\n";
});
go(function () {
    co::sleep(0.1);
});
swoole_event_wait();
?>
--EXPECT--
from=-1 create to=1
from=1 yield to=-1
from=-1 resume to=1
from=1 close to=-1
