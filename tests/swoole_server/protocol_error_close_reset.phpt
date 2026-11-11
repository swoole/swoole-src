--TEST--
swoole_server: malformed length and EOF packets preserve TCP reset and one onClose in BASE and PROCESS modes
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine\Client;
use Swoole\Server;
use function Swoole\Coroutine\run;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (['length', 'eof'] as $protocol) {
        $closes = new Atomic();
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $closes, $protocol) {
            run(function () use ($pm, $closes, $protocol) {
                $client = new Client(SWOOLE_SOCK_TCP);
                Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                // Exceed the server's minimum package_max_length of 64 KiB.
                $packet = $protocol === 'length'
                    ? pack('N', 131072) . str_repeat('x', 8192)
                    : str_repeat('x', 131072);
                Assert::same($client->send($packet), strlen($packet));
                Assert::false($client->recv(5));
                Assert::same($client->errCode, SOCKET_ECONNRESET);
                Assert::same($closes->get(), 1);
                $client->close();
            });
            $pm->kill();
        };
        $pm->childFunc = function () use ($pm, $mode, $protocol, $closes) {
            $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
            $server->set([
                'worker_num' => 1,
                'reactor_num' => 1,
                'enable_coroutine' => false,
                'package_max_length' => 65536,
                'open_length_check' => $protocol === 'length',
                'package_length_type' => 'N',
                'package_body_offset' => 4,
                'open_eof_check' => $protocol === 'eof',
                'package_eof' => "\r\n",
                'log_file' => '/dev/null',
            ]);
            $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
            $server->on('receive', function () { Assert::true(false); });
            $server->on('close', function () use ($closes) { $closes->add(); });
            $server->start();
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
