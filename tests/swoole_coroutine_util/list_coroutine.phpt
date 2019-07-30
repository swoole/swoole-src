--TEST--
swoole_coroutine_util: listCoroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$co_list = [];

foreach(range(1, 10) as $i) {
    $co_list[] = go(function () use ($i) {
        co::sleep(.4);
    });
}

go(function () use ($co_list) {
    co::sleep(.2);
    $coros = Co::listCoroutines();
    $list_2 = iterator_to_array($coros);
    Assert::same(array_values(array_diff($list_2, $co_list)), [Co::getUid(),]);
});

swoole_event_wait();

?>
--EXPECT--
