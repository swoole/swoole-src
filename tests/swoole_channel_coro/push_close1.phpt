--TEST--
swoole_channel_coro: push close 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();
$c1->close();

go(function () use ($c1) {
    $ret = $c1->push(1);
    echo "push ret:".var_export($ret,1)." error:".$c1->errCode."\n";
});
?>
--EXPECTF--
push ret:false error:-2
