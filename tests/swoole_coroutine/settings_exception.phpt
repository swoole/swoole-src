--TEST--
swoole_coroutine: configuration failures use exceptions across modules and preserve PHP exceptions
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
function rejected(callable $configure, string $option): void
{
    try {
        $configure();
        Assert::true(false, 'configuration must throw');
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::contains($exception->getMessage(), $option);
    }
}
set_error_handler(function ($severity, $message) {
    throw new RuntimeException($message);
});
try {
    $scheduler = new Swoole\Coroutine\Scheduler();
    $globalSetters = [
        fn ($options) => Swoole\Coroutine::set($options),
        fn ($options) => swoole_async_set($options),
        fn ($options) => $scheduler->set($options),
    ];
    if (class_exists(Swoole\Process\Pool::class)) {
        $pool = new Swoole\Process\Pool(1);
        $globalSetters[] = fn ($options) => $pool->set($options);
    }
    foreach ($globalSetters as $set) {
        rejected(fn () => $set(['socket_buffer_size' => -1]), 'socket_buffer_size');

    }
    rejected(fn () => Swoole\Coroutine::set(['name_resolver' => [new stdClass()]]), 'name_resolver');
    $marker = new RuntimeException('conversion failed');
    set_error_handler(function () use ($marker) { throw $marker; });
    foreach ($globalSetters as $set) {
        try {
            $set(['socket_connect_timeout' => new stdClass()]);
            Assert::true(false, 'conversion must throw');
        } catch (Throwable $caught) {
            Assert::same($caught, $marker);
        }
    }
    restore_error_handler();

    $http = new Swoole\Coroutine\Http\Client('127.0.0.1', 1);
    Assert::true($http->set(['timeout' => 1]));
    $snapshot = $http->setting;
    rejected(fn () => $http->set(['write_func' => 'missing_setting_callback']), 'callback');
    Assert::same($http->setting, $snapshot);
    Assert::true($http->set(['timeout' => 2]));
    Assert::same($snapshot['timeout'], 1);

    Swoole\Coroutine\run(function () {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        rejected(fn () => $socket->setProtocol(['package_length_func' => 'missing_setting_callback']), 'callback');
        rejected(fn () => $socket->setProtocol(['package_length_type' => '?']), 'package_length_type');
        Assert::true($socket->setProtocol(['package_length_type' => 'N']));
        $socket->close();

        foreach ([Swoole\Client::class, Swoole\Coroutine\Client::class] as $class) {
            $client = new $class(SWOOLE_SOCK_TCP);
            Assert::true($client->set(['package_eof' => '']));
            rejected(fn () => $client->connect('127.0.0.1', 1), 'package_eof');
            Assert::false($client->isConnected());
        }
        $http = new Swoole\Coroutine\Http\Client('127.0.0.1', 1);
        Assert::true($http->set(['http_proxy_host' => '127.0.0.1']));
        rejected(fn () => $http->get('/'), 'http_proxy_port');
        if (class_exists(Swoole\Coroutine\Http2\Client::class)) {
            $http2 = new Swoole\Coroutine\Http2\Client('127.0.0.1', 1);
            Assert::true($http2->set(['http_proxy_host' => '127.0.0.1']));
            rejected(fn () => $http2->connect(), 'http_proxy_port');
        }
    });
} finally {
    restore_error_handler();
}
echo "DONE\n";
?>
--EXPECT--
DONE
