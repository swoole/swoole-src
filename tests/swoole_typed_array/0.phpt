--TEST--
swoole_stdext/typed_array: 0
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$arr = typed_array(' <int>');

try {
    $array = typed_array('<int');
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains("must start with '<' and end with '>'"));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
