--TEST--
swoole_channel_coro: pop timeout 3
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();

go(function () use ($c1) {
    $ret = $c1->pop(1);
    echo "pop ret:".var_export($ret,1)." error:".$c1->errCode."\n";
});

go(function () use ($c1) {
    co::sleep(0.5);
    $ret = $c1->push("chan-1");
    echo "chan push ret:".var_export($ret,1)." error:".$c1->errCode."\n";
});
swoole_event_wait();
?>
--EXPECTF--
pop ret:'chan-1' error:0
chan push ret:true error:0
