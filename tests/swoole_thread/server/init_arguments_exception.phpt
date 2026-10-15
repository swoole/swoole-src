--TEST--
swoole_thread/server: init_arguments exceptions stop startup and remain catchable
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Assert::setThrowException(true);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_THREAD);
$exception = new RuntimeException('init_arguments failed');
Assert::true($server->set([
    'worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () use ($exception) {
        throw $exception;
    },
]));
$server->on('Receive', function () {});
$server->on('WorkerStart', function ($server) {
    echo "UNEXPECTED WORKER\n";
    $server->shutdown();
});
$settings = $server->setting;
set_error_handler(fn () => true);
try {
    try {
        $server->set(['init_arguments' => 42]);
        Assert::true(false, 'invalid init_arguments must throw');
    } catch (Swoole\Exception $caught) {
        Assert::same($caught->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    }
    Assert::same($server->setting, $settings);
} finally {
    restore_error_handler();
}
set_error_handler(function () use ($exception) {
    throw $exception;
});
try {
    $bootstrap = new class($exception) {
        public function __construct(private Throwable $exception) {}
        public function __toString(): string
        {
            throw $this->exception;
        }
    };
    try {
        $server->set(['bootstrap' => $bootstrap]);
        Assert::true(false, 'set() must throw');
    } catch (Throwable $caught) {
        Assert::same($caught, $exception);
        Assert::same($server->setting, $settings);
    }
    try {
        $server->set([
            'init_arguments' => fn () => [],
            'unsupported_test_option' => true,
        ]);
        Assert::true(false, 'set() must throw');
    } catch (Throwable $caught) {
        Assert::same($caught, $exception);
        Assert::same($server->setting, $settings);
    }
} finally {
    restore_error_handler();
}
try {
    $server->start();
    Assert::true(false, 'start() must throw');
} catch (Throwable $caught) {
    Assert::same($caught, $exception);
}
echo "DONE\n";
?>
--EXPECT--
DONE
