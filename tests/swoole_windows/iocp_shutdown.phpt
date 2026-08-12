--TEST--
swoole_windows: iocp shutdown drains pending operations
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    exit('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Socket::class, false)) {
    exit('skip coroutine socket not available');
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

    $coroutineId = go(function () use ($listener) {
        $listener->accept(-1);
    });

    Timer::after(1, static function () {
        Event::exit();
    });
});

Assert::true(Coroutine::cancel($coroutineId));
echo "DONE\n";
?>
--EXPECT--
DONE
