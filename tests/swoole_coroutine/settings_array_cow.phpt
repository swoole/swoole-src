--TEST--
settings updates preserve previously returned arrays and caller-owned input
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
$objects = [
    [$server, 'setting'],
    [$server->ports[0], 'setting'],
    [new Swoole\Client(SWOOLE_SOCK_TCP), 'setting'],
    [new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP), 'setting'],
    [new Swoole\Coroutine\Http\Client('127.0.0.1'), 'setting'],
    [new Swoole\Coroutine\Http2\Client('127.0.0.1'), 'setting'],
    [new Swoole\Coroutine\Http\Server('127.0.0.1', 0), 'settings'],
];
foreach ($objects as [$object, $property]) {
    $input = ['package_max_length' => 1024];
    $object->set($input);
    $snapshot = $object->$property;
    $object->set(['package_max_length' => 2048]);
    Assert::same($snapshot['package_max_length'], 1024, get_class($object));
    Assert::same($input, ['package_max_length' => 1024]);
    Assert::same($object->$property['package_max_length'], 2048);
}
echo "DONE\n";
?>
--EXPECT--
DONE
