--TEST--
swoole_server: pending output does not resume a paused connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use Swoole\Timer;

const OUTPUT_SIZE = 2 * 1024 * 1024;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(5);

$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    Assert::eq($client->send('first'), 5);
    $pm->wait();

    $data = '';
    while (strlen($data) < OUTPUT_SIZE) {
        $chunk = $client->recv();
        if (!$chunk) {
            break;
        }
        $data .= $chunk;
    }
    Assert::eq(strlen($data), OUTPUT_SIZE);

    Assert::eq($client->send('second'), 6);
    $pm->wait();
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $first = true;
    $resumed = false;
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'kernel_socket_send_buffer_size' => 128 * 1024,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Server $server, $fd) use ($pm, &$first, &$resumed) {
        if ($first) {
            $first = false;
            Assert::true($server->pause($fd));
            Timer::after(1000, function () use ($server, $fd, &$resumed) {
                $resumed = true;
                $server->resume($fd);
            });
            Assert::true($server->send($fd, str_repeat('A', OUTPUT_SIZE)));
            $pm->wakeup();
            return;
        }

        echo $resumed ? "RESUMED\n" : "EARLY\n";
        $pm->wakeup();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
RESUMED
