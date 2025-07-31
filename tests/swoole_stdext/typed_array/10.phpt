--TEST--
swoole_stdext/typed_array: 10
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$bytes = random_bytes(128);
$array = typed_array('<int, string>');
$array[999] = $bytes;
$copy = typed_array('<int, string>', $array);
Assert::eq($copy[999], $bytes);

try {
    $copy2 = typed_array('<string, string>', $array);
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('not match the initial values'));
    echo "DONE\n";
}


?>
--EXPECT--
DONE
