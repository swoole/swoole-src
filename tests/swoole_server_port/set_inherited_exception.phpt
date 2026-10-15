--TEST--
swoole_server_port: inherited configuration exceptions stop startup and remain catchable
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
$port = $server->listen('127.0.0.1', 0, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$exception = new RuntimeException('inherited configuration rejected');
$value = new class($exception) {
    public function __construct(private Throwable $exception) {}
    public function __toString(): string { throw $this->exception; }
};
Assert::true($server->set([
    'log_file' => '/dev/null',
    'worker_num' => 1,
    'ssl_cert_file' => $value,
    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
]));
$server->on('Receive', function () {});
$server->on('WorkerStart', function ($server) {
    echo "UNEXPECTED WORKER\n";
    $server->shutdown();
});
set_error_handler(function () use ($exception) {
    throw $exception;
});
try {
    $server->start();
    Assert::true(false, 'start() must throw');
} catch (Throwable $caught) {
    Assert::same($caught, $exception);
    Assert::null($port->setting);
} finally {
    restore_error_handler();
}
echo "DONE\n";
?>
--EXPECT--
DONE
