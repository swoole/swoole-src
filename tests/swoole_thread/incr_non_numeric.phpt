--TEST--
swoole_thread: incr and decr preserve non-numeric items
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$map = new Swoole\Thread\Map(['label' => 'ready', 1 => true, 'count' => 5]);
$list = new Swoole\Thread\ArrayList(['ready', true, 5.5]);

foreach ([[$map, 'label', 'ready'], [$map, 1, true], [$list, 0, 'ready'], [$list, 1, true]] as [$items, $key, $value]) {
    Assert::false($items->incr($key, 1));
    Assert::false($items->decr($key, 1));
    Assert::same($items[$key], $value);
}

Assert::same($map->incr('count', 2), 7);
Assert::same($list->decr(2, 0.5), 5.0);
echo "DONE\n";
?>
--EXPECT--
DONE
