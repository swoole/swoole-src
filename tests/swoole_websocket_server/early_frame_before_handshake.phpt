--TEST--
swoole_websocket_server: a frame sent while a custom handshake callback is pending is not dispatched
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$messages = new Atomic(0);

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $messages->set(0);
    $pm = new SwooleTest\ProcessManager;

    $pm->parentFunc = function () use ($pm, $messages) {
        Coroutine\run(function () use ($pm, $messages) {
            $upgrade = function (string $token) {
                return "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" .
                    "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" .
                    "X-Token: {$token}\r\n\r\n";
            };
            // masked text frame "hi"
            $frame = "\x81\x82\x00\x00\x00\x00hi";

            // rejected: the frame arrives while the callback waits for its lookup
            $cli = new Client(SWOOLE_SOCK_TCP);
            Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(), 2));
            $cli->send($upgrade('bad'));
            usleep(50000);
            $cli->send($frame);
            $response = '';
            while (($data = $cli->recv(2)) !== '' && $data !== false) {
                $response .= $data;
            }
            Assert::contains($response, '403 Forbidden');
            $cli->close();
            usleep(100000);
            Assert::same($messages->get(), 0);

            // accepted: frames after the 101 are dispatched
            $cli = new Client(SWOOLE_SOCK_TCP);
            Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(), 2));
            $cli->send($upgrade('good'));
            Assert::contains($cli->recv(2), '101 Switching Protocols');
            $cli->send($frame);
            Assert::same(substr($cli->recv(2), 2), 'hi');
            Assert::same($messages->get(), 1);
            $cli->close();
        });
        $pm->kill();
    };

    $pm->childFunc = function () use ($pm, $mode, $messages) {
        $serv = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $serv->set(['log_file' => '/dev/null', 'worker_num' => 1]);
        $serv->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $serv->on('Handshake', function (Request $request, Response $response) {
            Coroutine::sleep(0.3);
            if (($request->header['x-token'] ?? '') !== 'good') {
                $response->status(403);
                $response->end();
                return false;
            }
            $key = $request->header['sec-websocket-key'];
            $response->header('Upgrade', 'websocket');
            $response->header('Connection', 'Upgrade');
            $response->header('Sec-WebSocket-Accept', base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true)));
            $response->status(101);
            $response->end();
            return true;
        });
        $serv->on('Message', function (Server $serv, Frame $frame) use ($messages) {
            $messages->add();
            $serv->push($frame->fd, $frame->data);
        });
        $serv->start();
    };

    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
