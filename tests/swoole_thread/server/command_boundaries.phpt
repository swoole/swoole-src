--TEST--
swoole_thread/server: commands stay on the master VM and unsupported targets fail immediately
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Thread;
use Swoole\Timer;

Assert::setThrowException(true);
$main = Thread::getInfo()['is_main_thread'];
$server = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'task_enable_coroutine' => true,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $checked;
        $checked = new Thread\Atomic(0);
        return [$checked];
    },
]);

if ($main) {
    $warnings = 0;
    set_error_handler(function ($errno, $message) use (&$warnings) {
        Assert::contains($message, 'only MASTER command handlers');
        $warnings++;
        return true;
    });
    try {
        foreach ([
            SWOOLE_SERVER_COMMAND_MANAGER,
            SWOOLE_SERVER_COMMAND_EVENT_WORKER,
            SWOOLE_SERVER_COMMAND_TASK_WORKER,
            SWOOLE_SERVER_COMMAND_REACTOR_THREAD,
            SWOOLE_SERVER_COMMAND_MASTER | SWOOLE_SERVER_COMMAND_EVENT_WORKER,
        ] as $target) {
            Assert::false($server->addCommand('local', $target, fn () => 'unexpected'));
            Assert::same(swoole_last_error(), SWOOLE_ERROR_OPERATION_NOT_SUPPORT);
        }
    } finally {
        restore_error_handler();
    }
    Assert::same($warnings, 5);
    $owner = Thread::getNativeId();
    Assert::true($server->addCommand('local', SWOOLE_SERVER_COMMAND_MASTER, function ($server, $message) use ($owner) {
        Assert::same(Thread::getNativeId(), $owner);
        return $message;
    }));
}

$server->on('Start', function ($server) {
    Assert::same($server->command('local', 0, SWOOLE_SERVER_COMMAND_MASTER, ['value' => 42]), ['value' => 42]);
    foreach ([
        SWOOLE_SERVER_COMMAND_MANAGER,
        SWOOLE_SERVER_COMMAND_EVENT_WORKER,
        SWOOLE_SERVER_COMMAND_TASK_WORKER,
        SWOOLE_SERVER_COMMAND_REACTOR_THREAD,
    ] as $target) {
        Assert::false($server->command('local', 0, $target, []));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_OPERATION_NOT_SUPPORT);
    }
    // A rejected command must not prevent a subsequent local command from completing.
    Assert::same($server->command('local', 0, SWOOLE_SERVER_COMMAND_MASTER, ['value' => 43]), ['value' => 43]);
    $deadline = microtime(true) + 5;
    Timer::tick(10, function ($timer) use ($server, $deadline) {
        global $checked;
        if ($checked->get() === 2 || microtime(true) >= $deadline) {
            Timer::clear($timer);
            try {
                Assert::same($checked->get(), 2);
            } finally {
                $server->shutdown();
            }
        }
    });
});
$server->on('WorkerStart', function ($server) {
    Coroutine::create(function () use ($server) {
        [$checked] = Thread::getArguments();
        Assert::false($server->command('local', 0, SWOOLE_SERVER_COMMAND_MASTER, []));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_SERVER_UNRELATED_THREAD);
        $checked->add();
    });
});
$server->on('Receive', function () {});
$server->on('Task', function () {});
$server->start();
if ($main) {
    echo "DONE\n";
}
?>
--EXPECT--
DONE
