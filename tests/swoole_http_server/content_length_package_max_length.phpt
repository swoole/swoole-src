--TEST--
swoole_http_server: content length limit with a reused receive buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

const PACKAGE_MAX_LENGTH = 65537;

function warmupRequest(): string
{
    $body = str_repeat('W', PACKAGE_MAX_LENGTH);
    $headers = "POST /warmup HTTP/1.1\r\nHost: localhost\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
    $body = substr($body, strlen($headers));
    $headers = "POST /warmup HTTP/1.1\r\nHost: localhost\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
    $request = $headers . $body;
    Assert::same(strlen($request), PACKAGE_MAX_LENGTH);
    return $request;
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        Swoole\Coroutine\run(function () use ($pm) {
            foreach ([1, 1024 * 1024] as $contentLength) {
                foreach ([false, true] as $fragmented) {
                    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                    Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));

                    // An exact-limit request leaves a buffer rounded up to 65544 bytes on 64-bit hosts.
                    $request = warmupRequest();
                    Assert::same($socket->sendAll($request), strlen($request));
                    $response = '';
                    while (($data = $socket->recv()) !== '' && $data !== false) {
                        $response .= $data;
                        if (str_contains($response, "\r\n\r\nREADY")) {
                            break;
                        }
                    }
                    Assert::contains($response, 'HTTP/1.1 200 OK');
                    Assert::contains($response, "\r\n\r\nREADY");

                    // The header fits the reused buffer but exceeds the configured request limit.
                    $headers = "POST /oversized HTTP/1.1\r\nHost: localhost\r\n" .
                        "Content-Length: {$contentLength}\r\nConnection: close\r\nX-Pad: ";
                    $headers .= str_repeat('P', PACKAGE_MAX_LENGTH + 1 - strlen($headers) - 4) . "\r\n\r\n";
                    Assert::same(strlen($headers), PACKAGE_MAX_LENGTH + 1);
                    $request = $headers . ($contentLength === 1 ? 'X' : '');
                    $parts = $fragmented ? [substr($request, 0, 65536), substr($request, 65536)] : [$request];
                    foreach ($parts as $part) {
                        Assert::same($socket->sendAll($part), strlen($part));
                        if ($fragmented) {
                            usleep(1000);
                        }
                    }
                    Assert::true($socket->shutdown(STREAM_SHUT_WR));

                    $response = '';
                    while (($data = $socket->recv()) !== '' && $data !== false) {
                        $response .= $data;
                    }
                    Assert::contains($response, 'HTTP/1.1 413 Request Entity Too Large');
                    Assert::notContains($response, 'HTTP/1.1 200 OK');
                }
            }
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'log_file' => '/dev/null',
            'worker_num' => 1,
            'package_max_length' => PACKAGE_MAX_LENGTH,
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
            $response->end($request->server['request_uri'] === '/warmup' ? 'READY' : 'OVERSIZED');
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS
