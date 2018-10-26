--TEST--
swoole_coroutine: cid map max num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
co::set([
    'max_coroutine' => PHP_INT_MAX
]);
$cid_map = [];
while (true) {
    if (empty($cid_map)) {
        $cid = go(function () {
            co::yield();
            var_dump(co::getuid());
        });
    } else {
        $cid = go(function () { });
    }
    if (!isset($cid_map[$cid])) {
        $cid_map[$cid] = $cid;
    } else {
        $max = end($cid_map);
        assert($max === SWOOLE_MAX_CORO_NUM_LIMIT);
        var_dump($max);
        var_dump($cid);
        co::resume(1);
        break;
    }
}
?>
--EXPECTF--
int(%d)
int(2)
int(1)