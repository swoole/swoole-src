--TEST--
swoole_runtime/remote_object: IteratorAggregate supports fresh traversals and iterator cleanup
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
    $expected = ['first' => 10, 'second' => 20, 'third' => 30];
    $iterator = $client->create(ArrayIterator::class, $expected);
    Assert::same(iterator_to_array($iterator), $expected);
    Assert::same(iterator_to_array($iterator), $expected);

    $array = $client->create(ArrayObject::class, $expected);
    Assert::same(iterator_to_array($array), $expected);
    $array['fourth'] = 40;
    Assert::same(iterator_to_array($array), $expected + ['fourth' => 40]);
    $empty = $client->create(ArrayObject::class);
    Assert::same(iterator_to_array($empty), []);

    $aggregate = $client->create(RemoteObjectTestAggregate::class);
    Assert::same(iterator_to_array($aggregate), $expected);
    Assert::same(iterator_to_array($aggregate), $expected);
    Assert::same($aggregate->iteratorCount, 2);
    foreach ($aggregate as $key => $value) {
        if ($key === 'second') {
            break;
        }
    }
    Assert::same($client->call('remote_object_test_released_iterators'), 2);
    $aggregate->rewind();
    Assert::same($aggregate->key(), 'first');
    Assert::same($aggregate->current(), 10);
    Assert::same($aggregate->iteratorCount, 4);
    Assert::same($client->call('remote_object_test_released_iterators'), 3);
    unset($aggregate);
    remote_object_test_wait(static fn (): bool => $client->call('remote_object_test_released_iterators') === 4);
    Assert::same($client->call('remote_object_test_released_iterators'), 4);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
