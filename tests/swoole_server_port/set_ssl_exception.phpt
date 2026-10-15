--TEST--
swoole_server_port: SSL configuration failures preserve PHP exceptions
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
Assert::true($server->set([
    'worker_num' => 1,
    'log_file' => '/dev/null',
    'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
]));
$exception = new RuntimeException('SSL configuration rejected');
$value = new class($exception) {
    public function __construct(private Throwable $exception) {}
    public function __toString(): string
    {
        throw $this->exception;
    }
};
$options = [
    ['ssl_sni_certs' => ['localhost' => ['ssl_cert_file' => $value]]],
];
foreach (['ssl_cert_file', 'ssl_key_file', 'ssl_client_cert_file', 'ssl_cafile', 'ssl_capath',
    'ssl_ciphers', 'ssl_ecdh_curve', 'ssl_dhparam'] as $name) {
    $options[] = [$name => $value];
}

set_error_handler(function () use ($exception) {
    throw $exception;
});
try {
    foreach ([$server->ports[0], $server] as $target) {
        $settings = $target->setting;
        foreach ($options as $option) {
            try {
                $target->set($option);
                Assert::true(false, 'set() must throw');
            } catch (Throwable $caught) {
                Assert::same($caught, $exception);
            }
            Assert::same($target->setting, $settings);
        }
    }
} finally {
    restore_error_handler();
}

$warnings = 0;
set_error_handler(function () use (&$warnings) {
    $warnings++;
    return true;
});
try {
    foreach ([$server->ports[0], $server] as $target) {
        $settings = $target->setting;
        foreach ([['ssl_sni_certs' => true], ['ssl_sni_certs' => [[]]],
            ['ssl_sni_certs' => ['localhost' => true]]] as $option) {
            try {
                $target->set($option);
                Assert::true(false, 'invalid SNI settings must throw');
            } catch (Swoole\Exception $exception) {
                Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
            }
            Assert::same($target->setting, $settings);
        }
    }
} finally {
    restore_error_handler();
}
Assert::same($warnings, 0);
Assert::true($server->set(['ssl_ciphers' => 'DEFAULT']));
echo "DONE\n";
?>
--EXPECT--
DONE
