--TEST--
swoole_redis_server: getHandler returns the original callable or null
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function redis_test_handler(): string
{
    return 'function';
}
class RedisTestHandler
{
    public static function handleStatic(): string
    {
        return 'static';
    }
    public function handle(): string
    {
        return 'method';
    }
    public function __invoke(): string
    {
        return 'invokable';
    }
}

$server = new Swoole\Redis\Server('127.0.0.1', 0, SWOOLE_BASE);
$object = new RedisTestHandler;
$handlers = [
    'CLOSURE' => static fn () => 'closure',
    'FUNCTION' => 'redis_test_handler',
    'STATIC' => [RedisTestHandler::class, 'handleStatic'],
    'METHOD' => [$object, 'handle'],
    'INVOKABLE' => $object,
];
foreach ($handlers as $command => $handler) {
    Assert::true($server->setHandler($command, $handler));
    $actual = $server->getHandler(strtolower($command));
    Assert::same($actual, $handler);
    Assert::same($actual(), $handler());
}
foreach (['MISSING', '', str_repeat('x', 64)] as $command) {
    Assert::same($server->getHandler($command), null);
}
$type = (new ReflectionMethod($server, 'getHandler'))->getReturnType();
Assert::same($type->getName(), 'callable');
Assert::true($type->allowsNull());
echo "DONE\n";
?>
--EXPECT--
DONE
