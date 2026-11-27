--TEST--
swoole_server: sendwait works on an empty output queue and cannot overtake buffered data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Client;

Assert::setThrowException(true);
const BODY_LENGTH = 512 * 1024;
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        Coroutine\run(function () use ($pm) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set([
                'open_eof_check' => true,
                'package_eof' => "\n",
                'package_max_length' => BODY_LENGTH * 2,
            ]);
            try {
                Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                Assert::true($client->exportSocket()->setOption(SOL_SOCKET, SO_RCVBUF, 65536));
                Assert::same($client->send("direct\n"), 7);
                Assert::same($client->recv(), "direct-ok\n");
                Assert::same($client->send("queued\n"), 7);
                // Do not read until the server has checked its pending output and rejected sendwait().
                Assert::true($pm->wait());
                Assert::same($client->recv(), str_repeat('q', BODY_LENGTH) . "end\n");
            } finally {
                $client->close();
            }
        });
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'enable_coroutine' => false,
        'send_yield' => false,
        'socket_buffer_size' => BODY_LENGTH * 2,
        'kernel_socket_send_buffer_size' => 16384,
        'buffer_output_size' => BODY_LENGTH * 2,
        'open_eof_check' => true,
        'package_eof' => "\n",
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Receive', function ($server, $fd, $reactorId, $data) use ($pm) {
        if ($data === "direct\n") {
            Assert::true($server->sendwait($fd, "direct-ok\n"));
            return;
        }
        // This callback cannot yield. The small send buffer leaves pending asynchronous output.
        Assert::true($server->send($fd, str_repeat('q', BODY_LENGTH)));
        Assert::greaterThan($server->getClientInfo($fd)['send_queued_bytes'], 0);
        Assert::false($server->sendwait($fd, 'out-of-order'));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_OPERATION_NOT_SUPPORT);
        Assert::true($server->send($fd, "end\n"));
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
