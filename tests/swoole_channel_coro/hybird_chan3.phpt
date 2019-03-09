--TEST--
swoole_channel_coro: hybird channel select
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$size = 2;
$chan = new chan($size);
$coro_num = $size * 2;

go(function () use ($size, $chan) {
    for ($i=0; $i < $size; $i++) {
        $chan->push($i);
    }
});

for ($i=0; $i < $coro_num; $i++) {
    go(function () use ($i, $chan, $coro_num) {
        for ($j = 0; $j < $coro_num; $j ++) {
            $c = $chan->pop();
            echo  "@".$j . "->coro:" . $i . " pop chan id :" . var_export($c, 1) . PHP_EOL;
            co::sleep(0.2);
            $ret = $chan->push($c);
        }
    });
}
swoole_event::wait();
?>
--EXPECTF--
@0->coro:%d pop chan id :%d
@0->coro:%d pop chan id :%d
@0->coro:%d pop chan id :%d
@0->coro:%d pop chan id :%d
@1->coro:%d pop chan id :%d
@1->coro:%d pop chan id :%d
@1->coro:%d pop chan id :%d
@1->coro:%d pop chan id :%d
@2->coro:%d pop chan id :%d
@2->coro:%d pop chan id :%d
@2->coro:%d pop chan id :%d
@2->coro:%d pop chan id :%d
@3->coro:%d pop chan id :%d
@3->coro:%d pop chan id :%d
@3->coro:%d pop chan id :%d
@3->coro:%d pop chan id :%d
