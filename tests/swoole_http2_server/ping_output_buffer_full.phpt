--TEST--
swoole_http2_server: close the connection when a PING arrives while a response waits for the output buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Coroutine\System;
use Swoole\Http2\Request;

const RESPONSE_SIZE = 16 * 1024 * 1024;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1) . chr($type) . chr($flags) . pack('N', $streamId) . $payload;
}

function worker_pid(int $port): string
{
    $client = new Client('127.0.0.1', $port);
    Assert::true($client->connect());
    $request       = new Request();
    $request->path = '/pid';
    Assert::greaterThan($client->send($request), 0);
    $response = $client->recv(5);
    $client->close();
    Assert::isInstanceOf($response, Swoole\Http2\Response::class);
    return $response->data;
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        Co\run(function () use ($pm) {
            $port = $pm->getFreePort();
            $pid  = worker_pid($port);

            // A small receive buffer, so the response fills the server's output buffer while the client isn't reading.
            $socket = new Socket(AF_INET, SOCK_STREAM, 0);
            Assert::true($socket->setOption(SOL_SOCKET, SO_RCVBUF, 4096));
            Assert::true($socket->connect('127.0.0.1', $port, 2));
            $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                . http2_frame(4, 0, 0, pack('nN', 4, 0x7FFFFFFF))
                . http2_frame(8, 0, 0, pack('N', 0x7FFF0000))
                . http2_frame(1, 5, 1, "\x82\x86\x01\x09localhost\x04\x06/large");
            Assert::same($socket->sendAll($request), strlen($request));
            System::sleep(0.3);
            $ping = http2_frame(6, 0, 0, 'ABCDEFGH');
            Assert::same($socket->sendAll($ping), strlen($ping));

            // The server can't queue the PING ACK, so it closes the connection rather than leave it unanswered.
            do {
                $data = $socket->recv(65536, 5);
            } while (is_string($data) && $data !== '');
            $socket->close();
            Assert::same($data, '');

            Assert::same(worker_pid($port), $pid);
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num'          => 1,
            'open_http2_protocol' => true,
            'socket_buffer_size'  => 64 * 1024,
            'log_file'            => '/dev/null',
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) {
            $response->end($request->server['request_uri'] === '/pid' ? (string) getmypid() : str_repeat('a', RESPONSE_SIZE));
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
