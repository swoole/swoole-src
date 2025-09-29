--TEST--
swoole_thread: map
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\Map;

$uuid = uniqid();

$array = [
    'a' => random_int(1, 999999999999999999),
    'b' => random_bytes(128),
    'c' => $uuid,
    'd' => time(),
];

$m = new Map($array);
Assert::eq($m->toArray(), $array);
Assert::eq(count($m), count($array));
Assert::eq($m->find($uuid), 'c');

foreach ($array as $k => $v) {
    Assert::eq($m[$k], $array[$k]);
}

$array2 = [
    'key' => 'value',
    'hello' => 'world',
];
$m['map'] = $array2;
Assert::eq(count($m), 5);
Assert::eq($m['map']->toArray(), $array2);
Assert::eq(count($m['map']), count($array2));
Assert::eq($m['map']->values(), array_values($array2));
?>
--EXPECTF--
