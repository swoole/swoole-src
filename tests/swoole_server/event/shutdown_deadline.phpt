--TEST--
swoole_server/event: max_wait_time bounds master shutdown and permits early exit
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;
use Swoole\Server;
use Swoole\Timer;
use SwooleTest\Assert;
use SwooleTest\ProcessManager;

foreach (['timer', 'idle FD', 'drained'] as $blocker) {
    $pm = new ProcessManager;
    $pm->setWaitTimeout(5);
    $pm->childFirst();
    $pm->childFunc = function () use ($pm, $blocker) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'max_wait_time' => $blocker === 'drained' ? 30 : 1,
            'log_file' => '/dev/null',
        ]);
        $shutdownAt = null;
        $pair = null;
        $server->on('Receive', static function () {});
        $server->on('Start', static function (Server $server) use (&$shutdownAt) {
            $shutdownAt = hrtime(true);
            Assert::true($server->shutdown());
        });
        $server->on('BeforeShutdown', static function () use ($blocker, &$pair) {
            if ($blocker === 'timer') {
                Assert::true(Timer::tick(20, static function () {}) !== false);
            } elseif ($blocker === 'idle FD') {
                $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
                Assert::true(Event::add($pair[0], static function () {}) !== false);
            }
        });
        $server->on('Shutdown', static function () use ($pm, $blocker, &$shutdownAt) {
            $elapsed = (hrtime(true) - $shutdownAt) / 1e9;
            Assert::true($elapsed < 3.5);
            if ($blocker !== 'drained') {
                Assert::true($elapsed >= 0.95);
            }
            echo "$blocker: shutdown completed\n";
            $pm->wakeup();
        });
        Assert::true($server->start());
    };
    $pm->parentFunc = static function () {};
    $pm->run();
    Assert::same($pm->getChildExitStatus(), 0);
}
?>
--EXPECT--
timer: shutdown completed
idle FD: shutdown completed
drained: shutdown completed
