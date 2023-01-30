--TEST--
swoole_server/task: unpack
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server\Task;

$data1 = random_bytes(random_int(16, 8000));
$packed1 = Task::pack($data1);
Assert::eq($data1, Task::unpack($packed1));

$data2 = random_bytes(random_int(9000, 4 * 1024 * 1024));
$packed2 = Task::pack($data2);
Assert::eq($data2, Task::unpack($packed2));

$data3 = [
    'data' => random_bytes(random_int(16, 2000)),
    'msg' => 'data 3',
    'int' => random_int(1, 9999999),
    'uniq' => uniqid(),
];
$packed3 = Task::pack($data3);
Assert::same($data3, Task::unpack($packed3));

$data4 = [
    'data' => random_bytes(random_int(9000, 2 * 1024 * 1024)),
    'msg' => 'data 4',
    'int' => random_int(1, 9999999),
    'uniq' => uniqid(),
];
$packed4 = Task::pack($data4);
Assert::same($data4, Task::unpack($packed4));
?>
--EXPECT--
