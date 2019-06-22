--TEST--
swoole_channel_coro: pop timeout hanging up
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
exit("skip for hanging up");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();

go(function () use ($c1) {
    $ret = $c1->pop();
    echo "pop ret:".var_export($ret,1)." error:".$c1->errCode."\n";
});
?>
--EXPECTF--
