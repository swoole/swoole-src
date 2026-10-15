--TEST--
swoole_server_port: configuration exceptions propagate without committing settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
Assert::true($server->set(['worker_num' => 1, 'log_file' => '/dev/null']));
$port = $server->ports[0];
$exception = new RuntimeException('configuration rejected');
$value = new class($exception) {
    public function __construct(private Throwable $exception) {}
    public function __toString(): string
    {
        throw $this->exception;
    }
};

set_error_handler(function () use ($exception) {
    throw $exception;
});
try {
    foreach ([$port, $server] as $target) {
        $settings = $target->setting;
        foreach ([
            ['unsupported_test_option' => true],
            ['package_eof' => $value],
            ['package_eof' => $value, 'package_length_type' => new stdClass()],
            ['package_length_type' => $value],
            ['websocket_subprotocol' => $value],
            ['backlog' => new stdClass()],
            ['package_max_length' => new stdClass()],
        ] as $options) {
            try {
                $target->set($options);
                Assert::true(false, 'set() must throw');
            } catch (Throwable $caught) {
                Assert::same($caught, $exception);
            }
            Assert::same($target->setting, $settings);
        }
        Assert::true($target->set(['backlog' => 64]));
        Assert::same($target->setting['backlog'], 64);
        Assert::false(array_key_exists('backlog', $settings));
    }
    $settings = $server->setting;
    foreach ([
        ['worker_num' => new stdClass()],
        ['task_tmpdir' => $value],
        ['upload_tmp_dir' => $value],
        ['document_root' => $value],
        ['http_index_files' => [$value]],
        ['http_compression_types' => [$value]],
        ['static_handler_locations' => [$value]],
    ] as $options) {
        try {
            $server->set($options);
            Assert::true(false, 'set() must throw');
        } catch (Throwable $caught) {
            Assert::same($caught, $exception);
        }
        Assert::same($server->setting, $settings);
    }
} finally {
    restore_error_handler();
}

Assert::true($server->set(['worker_num' => 1]));
echo "DONE\n";
?>
--EXPECT--
DONE
