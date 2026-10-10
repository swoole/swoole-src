--TEST--
swoole_runtime/remote_object: cloning creates an independent remote object and relays clone errors
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\RemoteObject\Client;
use Swoole\RemoteObject\Exception;
use SwooleTest\Assert;

class RemoteObjectCloneable
{
    public int $cloneCount = 0;

    public function __clone(): void
    {
        $this->cloneCount++;
    }
}

class RemoteObjectUncloneable
{
    public string $value = 'original';

    private function __clone()
    {
    }
}

class RemoteObjectThrowingClone
{
    public string $value = 'original';

    public function __clone(): void
    {
        throw new DomainException('remote clone failed', 23);
    }
}

remote_object_test(static function (Client $client): void {
    $original = $client->create(ArrayObject::class, ['value' => 'original']);
    $copy = clone $original;
    Assert::true($copy->getObjectId() !== $original->getObjectId());
    $copy['value'] = 'copy';
    Assert::same($original['value'], 'original');
    Assert::same($copy['value'], 'copy');
    unset($copy);
    Assert::same($original['value'], 'original');

    $copy = clone $original;
    unset($original);
    Assert::same($copy['value'], 'original');
    unset($copy);

    $original = $client->create(RemoteObjectCloneable::class);
    $copy = clone $original;
    $secondCopy = clone $copy;
    Assert::same($original->cloneCount, 0);
    Assert::same($copy->cloneCount, 1);
    Assert::same($secondCopy->cloneCount, 2);
    Assert::true($secondCopy->getObjectId() !== $copy->getObjectId());

    $failures = [
        RemoteObjectUncloneable::class => Error::class,
        RemoteObjectThrowingClone::class => DomainException::class,
    ];
    foreach ($failures as $class => $errorClass) {
        $object = $client->create($class);
        try {
            $failedCopy = clone $object;
            throw new RuntimeException('Cloning must relay the remote exception');
        } catch (Exception $e) {
            Assert::same($e->getRemoteClass(), $errorClass);
            if ($errorClass === DomainException::class) {
                Assert::same($e->getRemoteCode(), 23);
                Assert::contains($e->getMessage(), 'remote clone failed');
            }
        }
        Assert::same($object->value, 'original');
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
