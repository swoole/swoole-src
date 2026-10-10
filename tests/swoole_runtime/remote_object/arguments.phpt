--TEST--
swoole_runtime/remote_object: argument decoding preserves named arguments, nested handles and cross-client calls
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\RemoteObject;
use Swoole\RemoteObject\Client;
use Swoole\RemoteObject\Exception;
use SwooleTest\Assert;

function remote_object_arguments_check(DateTimeInterface $date, array $nested, string $label): array
{
    return [$date->format('Y-m-d'), $nested['items'][0]->format('Y-m-d'), $label];
}

function remote_object_arguments_properties(object $object): array
{
    return remote_object_arguments_check($object->date, $object->nested, 'properties');
}

function remote_object_arguments_offsets(ArrayAccess $object): array
{
    return remote_object_arguments_check($object['date'], $object['nested'], 'offsets');
}

class RemoteObjectArgumentReceiver
{
    public array $values;

    public function __construct(DateTimeInterface $date, array $nested, string $label)
    {
        $this->values = remote_object_arguments_check($date, $nested, $label);
    }

    public function check(DateTimeInterface $date, array $nested, string $label): array
    {
        return remote_object_arguments_check($date, $nested, $label);
    }
}

remote_object_test(static function (Client $client, string $socket): void {
    $date = $client->create(DateTimeImmutable::class, '2026-01-02');
    $args = ['label' => 'named', 'nested' => ['items' => [$date]], 'date' => $date];
    $expected = ['2026-01-02', '2026-01-02', 'named'];
    Assert::same($client->call('remote_object_arguments_check', ...$args), $expected);
    $receiver = $client->create(RemoteObjectArgumentReceiver::class, ...$args);
    Assert::same($receiver->values, $expected);
    Assert::same($receiver->check(...$args), $expected);

    // Trusted clients on the same worker can pass each other's handles as arguments.
    $otherClient = new Client('unix://' . $socket);
    Assert::same($otherClient->call('remote_object_arguments_check', ...$args), $expected);

    $properties = $client->create(stdClass::class);
    $properties->date = $date;
    $properties->nested = $args['nested'];
    Assert::same($client->call('remote_object_arguments_properties', $properties), [
        '2026-01-02', '2026-01-02', 'properties',
    ]);
    $offsets = $client->create(ArrayObject::class);
    $offsets['date'] = $date;
    $offsets['nested'] = $args['nested'];
    Assert::same($client->call('remote_object_arguments_offsets', $offsets), [
        '2026-01-02', '2026-01-02', 'offsets',
    ]);

    $resource = $client->call('tmpfile');
    Assert::same($client->call('fwrite', $resource, 'hello'), 5);
    Assert::true($client->call('rewind', $resource));
    Assert::same($client->call('fread', $resource, 5), 'hello');
    Assert::true($client->call('fclose', $resource));

    $requests = [
        ['/new', ['class' => RemoteObjectArgumentReceiver::class]],
        ['/call_function', ['function' => 'remote_object_arguments_check']],
        ['/call_method', ['object' => $receiver->getObjectId(), 'method' => 'check']],
    ];
    foreach ($requests as [$path, $params]) {
        try {
            $client->execute($path, $params + ['args' => serialize(false)]);
            throw new RuntimeException('A non-array argument list must be reported');
        } catch (Exception $e) {
            Assert::contains($e->getMessage(), 'args must be an array');
        }
    }

    $released = $client->create(stdClass::class);
    $releasedId = $released->getObjectId();
    unset($released);
    remote_object_test_wait(static function () use ($client, $releasedId): bool {
        try {
            $client->execute('/isset_property', ['object' => $releasedId, 'property' => 'unused']);
            return false;
        } catch (Exception $e) {
            Assert::contains($e->getMessage(), "object[#{$releasedId}] not found");
            return true;
        }
    });
    $missing = RemoteObject::marshal($releasedId, Swoole\Coroutine::getCid(), $client->getId());
    $missingArgs = $args;
    $missingArgs['nested']['items'][0] = $missing;
    foreach ($requests as [$path, $params]) {
        try {
            $client->execute($path, $params + ['args' => serialize($missingArgs)]);
            throw new RuntimeException('A released handle in nested arguments must be reported');
        } catch (Exception $e) {
            Assert::contains($e->getMessage(), "object[#{$releasedId}] not found");
        }
    }

    $invalidId = $receiver->getObjectId() . 'invalid';
    try {
        $client->execute('/call_method', ['object' => $invalidId, 'method' => 'check', 'args' => serialize($args)]);
        throw new RuntimeException('An invalid handle must not resolve to an existing object');
    } catch (Exception $e) {
        Assert::contains($e->getMessage(), "object[#{$invalidId}] not found");
    }
    Assert::same($receiver->check(...$args), $expected);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
