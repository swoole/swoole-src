--TEST--
swoole_websocket_server: frames cannot precede the HTTP upgrade response
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\CloseFrame;
use Swoole\WebSocket\Server;

Assert::setThrowException(true);

function assertUpgradePending(Server $server, int $fd): void
{
    Assert::false($server->isEstablished($fd));
    $warnings = 0;
    set_error_handler(function () use (&$warnings) {
        ++$warnings;
        return true;
    });
    try {
        foreach ([
            fn () => $server->push($fd, 'too early'),
            fn () => $server->ping($fd, 'too early'),
            fn () => $server->disconnect($fd),
        ] as $send) {
            Assert::false($send());
            Assert::same(swoole_last_error(), SWOOLE_ERROR_WEBSOCKET_UNCONNECTED);
        }
    } finally {
        restore_error_handler();
    }
    Assert::same($warnings, 3);
    Assert::false($server->isEstablished($fd));
}

class PendingUpgradeHeader
{
    public function __construct(private Server $server, private int $fd) {}
    public function __toString(): string
    {
        // Header encoding can enter PHP and yield before any response bytes are submitted.
        assertUpgradePending($this->server, $this->fd);
        if (Coroutine::getCid() > 0) {
            Coroutine::sleep(0.001);
        }
        assertUpgradePending($this->server, $this->fd);
        return 'encoded';
    }
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        foreach (['default', 'custom', 'defer'] as $handshake) {
            $pm = new ProcessManager;
            $pm->parentFunc = function () use ($pm, $tls, $handshake) {
                try {
                    Coroutine\run(function () use ($pm, $tls, $handshake) {
                        $client = new Client('127.0.0.1', $pm->getFreePort(), $tls);
                        $client->set(['timeout' => 3, 'open_websocket_ping_frame' => true, 'open_websocket_close_frame' => true]);
                        try {
                            Assert::true($client->upgrade('/'));
                            Assert::same($client->headers['x-upgrade-phase'], 'encoded');
                            Assert::same($client->recv()->data, 'ready');
                            $ping = $client->recv();
                            Assert::same($ping->opcode, WEBSOCKET_OPCODE_PING);
                            Assert::same($ping->data, 'ready-ping');
                            if ($handshake === 'defer') {
                                Assert::same($client->recv()->data, 'deferred');
                            }
                            Assert::true($client->push('finish'));
                            $close = $client->recv();
                            Assert::isInstanceOf($close, CloseFrame::class);
                            Assert::same($close->reason, 'done');
                        } finally {
                            $client->close();
                        }
                    });
                } finally {
                    $pm->kill();
                }
            };
            $pm->childFunc = function () use ($pm, $mode, $tls, $handshake) {
                $server = new Server('127.0.0.1', $pm->getFreePort(), $mode, SWOOLE_SOCK_TCP | ($tls ? SWOOLE_SSL : 0));
                $server->set([
                    'worker_num' => 1,
                    'reactor_num' => 1,
                    'log_file' => '/dev/null',
                ] + ($tls ? [
                    'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
                    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
                ] : []));
                $server->on('workerStart', fn () => $pm->wakeup());
                $ready = function (Server $server, Request $request) {
                    Assert::true($server->isEstablished($request->fd));
                    Assert::true($server->push($request->fd, 'ready'));
                    Assert::true($server->ping($request->fd, 'ready-ping'));
                };
                if ($handshake === 'custom') {
                    $server->on('handshake', function (Request $request, Response $response) use ($server, $ready) {
                        assertUpgradePending($server, $request->fd);
                        $response->header('Upgrade', 'websocket');
                        $response->header('Connection', 'Upgrade');
                        $response->header('Sec-WebSocket-Accept', base64_encode(sha1(
                            $request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true
                        )));
                        $response->header('X-Upgrade-Phase', new PendingUpgradeHeader($server, $request->fd));
                        $response->status(101);
                        Assert::true($response->end());
                        Swoole\Event::defer(fn () => $ready($server, $request));
                        return true;
                    });
                } else {
                    $server->on('beforeHandshakeResponse', function (Server $server, Request $request, Response $response) use ($handshake) {
                        assertUpgradePending($server, $request->fd);
                        if ($handshake === 'defer') {
                            // A non-yielding handshake returns and sends its 101 before this deferred task runs.
                            $response->header('X-Upgrade-Phase', 'encoded');
                            Swoole\Event::defer(function () use ($server, $request) {
                                Assert::true($server->isEstablished($request->fd));
                                Assert::true($server->push($request->fd, 'deferred'));
                            });
                        } else {
                            $response->header('X-Upgrade-Phase', new PendingUpgradeHeader($server, $request->fd));
                        }
                    });
                    $server->on('open', $ready);
                }
                $server->on('message', function (Server $server, $frame) {
                    Assert::same($frame->data, 'finish');
                    Assert::true($server->disconnect($frame->fd, WEBSOCKET_CLOSE_NORMAL, 'done'));
                    Assert::false($server->isEstablished($frame->fd));
                });
                $server->start();
            };
            $pm->childFirst();
            $pm->run();
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
