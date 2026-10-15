--TEST--
swoole_runtime/remote_object: native method dispatch supports __call and relays invocation errors
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

class RemoteObjectMagicMethods
{
    public function direct(string $value): string
    {
        return 'direct:' . $value;
    }

    public function __call(string $method, array $args): array
    {
        if ($method === 'fail') {
            throw new DomainException('magic method failed', 17);
        }
        return ['method' => $method, 'args' => $args];
    }

    private function hidden(): void
    {
    }
}

class RemoteObjectPlainMethods
{
    public function direct(): string
    {
        return 'OK';
    }

    private function hidden(): void
    {
    }

    protected function guarded(): void
    {
    }
}

remote_object_test(static function (Client $client): void {
    $magic = $client->create(RemoteObjectMagicMethods::class);
    Assert::same($magic->direct('value'), 'direct:value');
    Assert::same($magic->dynamic('value', 42), ['method' => 'dynamic', 'args' => ['value', 42]]);
    Assert::same($magic->dynamic(answer: 42), ['method' => 'dynamic', 'args' => ['answer' => 42]]);
    Assert::same($magic->hidden(), ['method' => 'hidden', 'args' => []]);
    try {
        $magic->fail();
        throw new RuntimeException('The exception from __call must be relayed');
    } catch (Exception $e) {
        Assert::same($e->getRemoteClass(), DomainException::class);
        Assert::same($e->getRemoteCode(), 17);
        Assert::contains($e->getMessage(), 'magic method failed');
    }

    $plain = $client->create(RemoteObjectPlainMethods::class);
    foreach (['missing' => 'undefined method', 'hidden' => 'private method', 'guarded' => 'protected method'] as $method => $message) {
        try {
            $plain->{$method}();
            throw new RuntimeException('An invalid method call must fail');
        } catch (Exception $e) {
            Assert::same($e->getRemoteClass(), Error::class);
            Assert::contains($e->getMessage(), $message);
        }
        Assert::same($plain->direct(), 'OK');
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
