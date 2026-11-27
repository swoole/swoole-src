--TEST--
swoole_server: pausing with pending output retains buffered EOF frames until resume
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

Assert::setThrowException(true);
const OUTPUT_LENGTH = 512 * 1024;
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $control = new Client(SWOOLE_SOCK_TCP);
    try {
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        Assert::true($control->connect('127.0.0.1', $pm->getFreePort(), 5));
        Assert::same($client->send("first\nsecond\n"), 13);
        $pm->wait();
        // Resume through a separate connection. No further data is sent to the paused connection.
        Assert::same($control->send("resume\n"), 7);
        Assert::same($control->recv(), "OK\n");
        $reply = '';
        while (strlen($reply) < OUTPUT_LENGTH + 5) {
            $chunk = $client->recv();
            Assert::stringNotEmpty($chunk);
            $reply .= $chunk;
        }
        Assert::same($reply, str_repeat('A', OUTPUT_LENGTH) . "DONE\n");
    } finally {
        $client->close();
        $control->close();
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'enable_coroutine' => false,
        'send_yield' => false,
        'kernel_socket_send_buffer_size' => 16384,
        'open_eof_split' => true,
        'package_eof' => "\n",
        'log_file' => '/dev/null',
    ]);
    $fd = null;
    $resumed = false;
    $packets = 0;
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Receive', function (Server $server, int $session, int $reactorId, string $data)
        use ($pm, &$fd, &$resumed, &$packets) {
        if ($data === "resume\n") {
            $resumed = true;
            Assert::true($server->resume($fd));
            Assert::true($server->send($session, "OK\n"));
            return;
        }
        $packets++;
        if ($data === "first\n") {
            Assert::same($packets, 1);
            $fd = $session;
            Assert::true($server->send($fd, str_repeat('A', OUTPUT_LENGTH)));
            Assert::greaterThan($server->getClientInfo($fd)['send_queued_bytes'], 0);
            Assert::true($server->pause($fd));
            $pm->wakeup();
        } else {
            Assert::same($data, "second\n");
            Assert::true($resumed, 'second packet must wait for resume');
            Assert::same($packets, 2);
            Assert::true($server->send($fd, "DONE\n"));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
