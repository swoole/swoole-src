--TEST--
swoole_http2_server: reject truncated multipart streams and replace Content-Type state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function frame(int $type, int $flags, int $stream, string $data = ''): string
{
    return substr(pack('N', strlen($data)), 1) . chr($type) . chr($flags) . pack('N', $stream) . $data;
}

function read_exact($socket, int $length): string
{
    $data = '';
    while (strlen($data) < $length) {
        $part = fread($socket, $length - strlen($data));
        if ($part === false || $part === '') {
            throw new RuntimeException('HTTP/2 response ended or timed out');
        }
        $data .= $part;
    }
    return $data;
}

function repeated_content_type(ProcessManager $pm, array $types, string $body): array
{
    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $error, 2);
    Assert::notSame($socket, false);
    stream_set_timeout($socket, 2);
    // Static HPACK indexes: POST, http, /, and an unindexed :authority.
    $headers = "\x83\x86\x84\x01\x09localhost";
    foreach ($types as $type) {
        // Literal Content-Type using static name index 31, without dynamic table entries.
        $headers .= "\x0f\x10" . chr(strlen($type)) . $type;
    }
    $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . frame(4, 0, 0)
        . frame(1, 4, 1, $headers) . frame(0, 1, 1, $body);
    Assert::same(fwrite($socket, $data), strlen($data));
    $response = '';
    do {
        $head    = read_exact($socket, 9);
        $length  = unpack('N', "\0" . substr($head, 0, 3))[1];
        $type    = ord($head[3]);
        $flags   = ord($head[4]);
        $stream  = unpack('N', substr($head, 5))[1] & 0x7FFFFFFF;
        $payload = $length ? read_exact($socket, $length) : '';
        if ($type === 4 && $flags === 0) {
            fwrite($socket, frame(4, 1, 0));
        }
        if ($stream === 1 && $type === 0) {
            $response .= $payload;
        }
    } while ($stream !== 1 || !in_array($type, [0, 1], true) || !($flags & 1));
    fclose($socket);
    $result = json_decode($response, true);
    Assert::true(is_array($result));
    return $result;
}

$pm             = new ProcessManager();
$dir            = sys_get_temp_dir() . '/swoole-http2-upload-' . getmypid();
Assert::true(mkdir($dir));
$pm->parentFunc = function () use ($pm, $dir) {
    try {
        Swoole\Coroutine\run(function () use ($pm) {
            $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
            $client->set(['timeout' => 2]);
            Assert::true($client->connect());
            foreach ([false, true] as $complete) {
                $body = "--review\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\npayload";
                if ($complete) {
                    $body .= "\r\n--review\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--review--\r\n";
                }
                $request          = new Swoole\Http2\Request();
                $request->method  = 'POST';
                $request->headers = ['content-type' => 'multipart/form-data; boundary=review'];
                $request->data    = $body;
                Assert::greaterThan($client->send($request), 0);
                $response = $client->recv();
                Assert::notSame($response, false);
                Assert::same($response->statusCode, $complete ? 200 : 400);
                if ($complete) {
                    Assert::same(json_decode($response->data, true)['post'], ['x' => 'value']);
                }
            }
            $client->close();
        });
        $result = repeated_content_type($pm, ['multipart/form-data; boundary=old', 'text/plain'], 'raw');
        Assert::null($result['post']);
        Assert::same($result['body'], 'raw');
        $body   = "--review\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--review--\r\n";
        $result = repeated_content_type($pm, ['application/x-www-form-urlencoded', 'multipart/form-data; boundary=review'], $body);
        Assert::same($result['post'], ['x' => 'value']);
        $deadline = microtime(true) + 2;
        while (glob($dir . '/swoole.upfile.*') && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same(glob($dir . '/swoole.upfile.*'), []);
    } finally {
        $pm->kill();
        foreach (glob($dir . '/swoole.upfile.*') as $path) {
            unlink($path);
        }
        Assert::true(rmdir($dir));
    }
};
$pm->childFunc = function () use ($pm, $dir) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'open_http2_protocol' => true, 'upload_tmp_dir' => $dir]);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, $response) {
        $response->end(json_encode(['post' => $request->post, 'body' => $request->rawContent()]));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
