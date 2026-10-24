--TEST--
swoole_client_async: enforce package_max_length with eof protocol
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_async_set(['log_level' => SWOOLE_LOG_NONE]);

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $cases = [
        ['complete', false],
        ['unterminated', false],
        ['split', true],
    ];
    $outcomes = [];

    $start = function (string $command, bool $split) use (&$outcomes, $cases, $pm) {
        $received = false;
        $timedOut = false;
        $timer = null;

        $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_eof_check' => true,
            'open_eof_split' => $split,
            'package_eof' => "\r\n",
            'package_max_length' => 1024,
        ]);
        $client->on('connect', function (Swoole\Async\Client $client) use ($command) {
            $client->send($command);
        });
        $client->on('receive', function (Swoole\Async\Client $client) use (&$received) {
            $received = true;
            $client->close();
        });
        $client->on('error', function () {
            Assert::true(false);
        });
        $client->on('close', function () use (
            &$outcomes, &$received, &$timedOut, &$timer, $command, $cases, $pm
        ) {
            if (!$timedOut) {
                Swoole\Timer::clear($timer);
            }
            $outcomes[$command] = [$received, swoole_last_error(), $timedOut];
            if (count($outcomes) === count($cases)) {
                $pm->kill();
                Swoole\Event::exit();
            }
        });
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $timer = Swoole\Timer::after(2000, function () use (&$timedOut, $client) {
            $timedOut = true;
            $client->close();
        });
    };

    foreach ($cases as [$command, $split]) {
        $start($command, $split);
    }
    Swoole\Event::wait();

    foreach ($cases as [$command]) {
        Assert::false($outcomes[$command][0]);
        Assert::same($outcomes[$command][1], SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE);
        Assert::false($outcomes[$command][2]);
    }
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, int $fd, int $reactorId, string $command) {
        if ($command === 'unterminated') {
            $server->send($fd, str_repeat('A', 2000));
        } else {
            $server->send($fd, str_repeat('A', 1023));
            Swoole\Timer::after(50, function () use ($server, $fd) {
                $server->send($fd, "\r\n");
            });
        }
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
