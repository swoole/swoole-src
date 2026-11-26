--TEST--
swoole_server: malformed length and EOF packets close once in BASE and PROCESS modes
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
    foreach (['length', 'eof', 'eof_complete', 'eof_split'] as $protocol) {
        $closes = new Atomic();
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $closes, $protocol) {
            run(function () use ($pm, $closes, $protocol) {
                $client = new Client(SWOOLE_SOCK_TCP);
                Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                $packet = match ($protocol) {
                    'length' => pack('N', 131072) . str_repeat('x', 8192),
                    'eof' => str_repeat('x', 131072),
                    default => str_repeat('x', 65536) . "\r\n",
                };
                Assert::same($client->send($packet), strlen($packet));
                $received = $client->recv(5);
                if ($protocol === 'length' || $protocol === 'eof' || $received === false) {
                    Assert::false($received);
                    Assert::same($client->errCode, SOCKET_ECONNRESET);
                } else {
                    // The parser can consume the whole oversized packet before closing the socket.
                    Assert::same($received, '');
                }
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
                // An unaligned limit lets the buffer grow beyond it, even when EOF fits in the same read.
                'package_max_length' => $protocol === 'eof_complete' || $protocol === 'eof_split' ? 65537 : 65536,
                'open_length_check' => $protocol === 'length',
                'package_length_type' => 'N',
                'package_body_offset' => 4,
                'open_eof_check' => $protocol !== 'length',
                'open_eof_split' => $protocol === 'eof_split',
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
