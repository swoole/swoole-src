--TEST--
swoole_stdext/typed_array: 5
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = typed_array('<int>');
$array[] = 3;
$array[] = 5;
$array[] = 7;
$array[3] = random_int(1, 100);

try {
    $array[5] = 999;
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('out of the permitted range'));
    echo "DONE\n";
}

try {
    $array["hello"] = 999;
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('must be undef or int'));
    echo "DONE\n";
}

?>
--EXPECT--
DONE
DONE
