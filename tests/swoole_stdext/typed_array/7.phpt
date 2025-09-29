--TEST--
swoole_stdext/typed_array: 7
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$num = random_int(1, 1000);
$array = typed_array('<int>', [1, $num, 3]);

$copy = [];
foreach($array as $k => $v) {
    $copy[] = $v;
    $array[$k] = $v * 2;
}

Assert::eq($copy[1], $num);
Assert::eq($array[1], $num * 2);
Assert::true($array->isTyped());

try {
    $array[] = 'hello';
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}

foreach($copy as &$v) {
    $v = 0;
}
Assert::eq($copy->sum(), 0);

try {
    foreach ($array as &$v) {
        var_dump($v);
    }
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('not support using references for element value'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
DONE
