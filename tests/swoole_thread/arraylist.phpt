--TEST--
swoole_thread: arraylist
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\ArrayList;

$array = [
    random_int(1, 999999999999999999),
    random_bytes(128),
    uniqid(),
    time(),
];

$l = new ArrayList($array);
Assert::eq(count($l), count($array));
Assert::eq($l->toArray(), $array);

for ($i = 0; $i < count($array); $i++) {
    Assert::eq($l[$i], $array[$i]);
}

$array2 = [
    'key' => 'value',
    'hello' => 'world',
];
$l[] = $array2;

Assert::eq(count($l), 5);
Assert::eq($l[4]->toArray(), $array2);

try {
    $l2 = new ArrayList($array2);
    echo "never here\n";
} catch (Throwable $e) {
    Assert::contains($e->getMessage(), 'must be an array of type list');
}
?>
--EXPECTF--
