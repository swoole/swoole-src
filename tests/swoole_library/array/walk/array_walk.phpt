--TEST--
swoole_library/array/walk: array_walk() tests
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

function foo($v1, $v2, $v3)
{
    var_dump($v1);
    var_dump($v2);
    var_dump($v3);
}

$var = [1, 2];
var_dump(array_walk($var, "foo", "data"));

function foo2($v1, $v2, $v3)
{
    throw new Exception($v3);
}

try {
    var_dump(array_walk($var, "foo2", "data"));
} catch (Exception $e) {
    var_dump($e->getMessage());
}

echo "Done\n";
?>
--EXPECTF--
int(1)
int(0)
string(4) "data"
int(2)
int(1)
string(4) "data"
bool(true)
string(4) "data"
Done
