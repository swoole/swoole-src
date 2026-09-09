--TEST--
swoole_http2_client_coro: split request data by the peer frame limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;
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
    Swoole\Coroutine::set(['http2_max_frame_size' => 65536]);
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());

        $request = new Swoole\Http2\Request;
        Assert::greaterThan($client->send($request), 0);
        Assert::notSame($client->recv(), false);

        $request = new Swoole\Http2\Request;
        $request->data = str_repeat('a', 40000);
        Assert::greaterThan($client->send($request), 0);
        Assert::notSame($client->recv(), false);

        $request = new Swoole\Http2\Request;
        $request->pipeline = true;
        $streamId = $client->send($request);
        Assert::greaterThan($streamId, 0);
        Assert::true($client->write($streamId, str_repeat('a', 100000), true));
        Assert::notSame($client->recv(), false);
        $client->close();
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle(function (Connection $connection) use ($server) {
            $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 5, 16384));
            Assert::same($connection->send($settings), strlen($settings));

            $buffer = '';
            $dataLengths = [];
            $pipelineLengths = [];
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

                while (strlen($buffer) >= 9) {
                    $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
                    if (strlen($buffer) < 9 + $length) {
                        break;
                    }

                    $type = ord($buffer[3]);
                    $flags = ord($buffer[4]);
                    $streamId = unpack('N', substr($buffer, 5, 4))[1] & 0x7fffffff;
                    $buffer = substr($buffer, 9 + $length);

                    if ($type === SWOOLE_HTTP2_TYPE_HEADERS && $streamId === 1) {
                        $response = http2_frame(
                            SWOOLE_HTTP2_TYPE_HEADERS,
                            HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                            1,
                            "\x88"
                        );
                        Assert::same($connection->send($response), strlen($response));
                    } elseif ($type === SWOOLE_HTTP2_TYPE_DATA && $streamId === 3) {
                        $dataLengths[] = $length;
                        if (($flags & HTTP2_FLAG_END_STREAM) !== 0) {
                            Assert::same($dataLengths, [16384, 16384, 7232]);
                            $settings = http2_frame(
                                SWOOLE_HTTP2_TYPE_SETTINGS,
                                0,
                                0,
                                pack('nN', 5, 65536)
                            );
                            Assert::same($connection->send($settings), strlen($settings));
                            $response = http2_frame(
                                SWOOLE_HTTP2_TYPE_HEADERS,
                                HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                                3,
                                "\x88"
                            );
                            Assert::same($connection->send($response), strlen($response));
                        }
                    } elseif ($type === SWOOLE_HTTP2_TYPE_DATA && $streamId === 5) {
                        $pipelineLengths[] = $length;
                        if (($flags & HTTP2_FLAG_END_STREAM) !== 0) {
                            Assert::same($pipelineLengths, [65536, 34464]);
                            $response = http2_frame(
                                SWOOLE_HTTP2_TYPE_HEADERS,
                                HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                                5,
                                "\x88"
                            );
                            Assert::same($connection->send($response), strlen($response));
                            $connection->close();
                            $server->shutdown();
                            return;
                        }
                    }
                }
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
