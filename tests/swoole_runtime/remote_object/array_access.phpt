--TEST--
swoole_runtime/remote_object: ArrayAccess preserves offsets and array semantics
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\RemoteObject\Client;
use SwooleTest\Assert;

remote_object_test(static function (Client $client): void {
    $array = $client->create(ArrayObject::class, ['name' => 'Alice', 'nil' => null, 3 => 'third', '' => 'empty']);
    Assert::same($array['name'], 'Alice');
    Assert::same($array[3], 'third');
    Assert::same($array[''], 'empty');
    Assert::true(isset($array['name']));
    Assert::false(isset($array['nil']));
    Assert::false(isset($array['missing']));
    $array['name'] = 'Bob';
    $array[''] = 'updated';
    $array[] = 'appended';
    unset($array[3]);
    Assert::same($array->getArrayCopy(), ['name' => 'Bob', 'nil' => null, '' => 'updated', 4 => 'appended']);
    Assert::false(isset($array[3]));

    $date = $client->create(DateTimeImmutable::class, '2026-01-02');
    $array['date'] = $date;
    Assert::same($array['date']->format('Y-m-d'), '2026-01-02');
    unset($array['date']);

    $storage = $client->create(SplObjectStorage::class);
    $key = $client->create(stdClass::class);
    $storage[$key] = 'object offset';
    Assert::true(isset($storage[$key]));
    Assert::same($storage[$key], 'object offset');
    unset($storage[$key]);
    Assert::false(isset($storage[$key]));
    echo "DONE\n";
});
?>
--EXPECT--
DONE
