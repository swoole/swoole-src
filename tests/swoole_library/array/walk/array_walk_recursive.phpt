--TEST--
swoole_library/array/walk: array_walk_recursive.phptTest array_walk_recursive()
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

function foo($value)
{
    echo $value . " foo\n";
}

function bar($value)
{
    echo $value . " bar\n";
}

$arr = [1, 2, 3];
var_dump(array_walk_recursive($arr, 'foo'));
var_dump(array_walk_recursive($arr, 'bar'));

?>
--EXPECT--
1 foo
2 foo
3 foo
bool(true)
1 bar
2 bar
3 bar
bool(true)
