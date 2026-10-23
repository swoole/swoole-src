--TEST--
swoole_windows: iocp shutdown drains pending operations
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Socket::class, false)) {
    die('skip coroutine socket not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use Swoole\Event;
use Swoole\Timer;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

$coroutineId = null;
Coroutine::set(['enable_deadlock_check' => false]);

run(function () use (&$coroutineId) {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());

    $server = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
    Assert::assert($server !== false, $errorMessage ?: 'failed to create socket server');
    Assert::integer(Event::add($server, static function () {}));

    $coroutineId = go(function () use ($listener) {
        $listener->accept(-1);
    });

    Timer::after(1, static function () {
        Event::exit();
    });
});

// run() has destroyed the scheduler. A pending IOCP operation must be drained
// during shutdown without resuming PHP on that destroyed scheduler.
Assert::true(Coroutine::exists($coroutineId));
Assert::false(Coroutine::cancel($coroutineId));
Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANNOT_CANCEL);
echo "DONE\n";
?>
--EXPECT--
DONE
