--TEST--
swoole_http2_client_coro: respect peer header frame limits
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;
const HTTP2_FRAME_HEADER_SIZE = 9;
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());

        $cookieRequest = new Swoole\Http2\Request;
        $cookieRequest->cookies = ['token' => str_repeat('0', 4097)];
        try {
            $client->send($cookieRequest);
        } catch (Swoole\Coroutine\Http2\Client\Exception $exception) {
        }
        Assert::isInstanceOf($exception ?? null, Swoole\Coroutine\Http2\Client\Exception::class);
        Assert::true($client->connected);

        $request = new Swoole\Http2\Request;
        $request->headers = ['x-large' => str_repeat('0', 40000)];

        $exception = null;
        try {
            $client->send($request);
        } catch (Swoole\Coroutine\Http2\Client\Exception $exception) {
        }
        $closed = !$client->connected;
        if ($client->connected) {
            $client->close();
        }

        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());

        $request = new Swoole\Http2\Request;
        Assert::greaterThan($client->send($request), 0);
        Assert::notSame($client->recv(), false);

        $request = new Swoole\Http2\Request;
        $request->headers = ['x-large' => str_repeat('0', 100000)];
        $accepted = $client->send($request);
        if ($accepted !== false) {
            $response = $client->recv();
        }
        $connected = $client->connected;
        if ($client->connected) {
            $client->close();
        }

        Assert::isInstanceOf($exception, Swoole\Coroutine\Http2\Client\Exception::class);
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::same($exception->getMessage(), 'HTTP/2 header block is too large');
        Assert::true($closed);
        Assert::greaterThan($accepted, 0);
        Assert::notSame($response ?? false, false);
        Assert::true($connected);
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $connectionCount = 0;
        $server->handle(function (Connection $connection) use ($server, &$connectionCount) {
            $thisConnection = ++$connectionCount;
            $maxFrameSize = $thisConnection === 2 ? 1 << 20 : 1 << 14;
            $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 5, $maxFrameSize));
            Assert::same($connection->send($settings), strlen($settings));

            $buffer = '';
            $prefaceReceived = false;
            while (($data = $connection->recv()) !== '' && $data !== false) {
                $buffer .= $data;
                if (!$prefaceReceived) {
                    if (strlen($buffer) < strlen(HTTP2_PREFACE)) {
                        continue;
                    }
                    Assert::same(substr($buffer, 0, strlen(HTTP2_PREFACE)), HTTP2_PREFACE);
                    $buffer = substr($buffer, strlen(HTTP2_PREFACE));
                    $prefaceReceived = true;
                }

                while (strlen($buffer) >= HTTP2_FRAME_HEADER_SIZE) {
                    $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
                    if (strlen($buffer) < HTTP2_FRAME_HEADER_SIZE + $length) {
                        break;
                    }

                    $type = ord($buffer[3]);
                    $streamId = unpack('N', substr($buffer, 5, 4))[1] & 0x7fffffff;
                    $buffer = substr($buffer, HTTP2_FRAME_HEADER_SIZE + $length);
                    if ($type === SWOOLE_HTTP2_TYPE_HEADERS) {
                        $response = http2_frame(
                            SWOOLE_HTTP2_TYPE_HEADERS,
                            HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                            $streamId,
                            "\x88"
                        );
                        Assert::same($connection->send($response), strlen($response));
                    }
                }
            }
            $connection->close();
            if ($thisConnection === 2) {
                $server->shutdown();
            }
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
