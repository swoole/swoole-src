--TEST--
swoole_http2_server: sendfile range, partial window, trailers and metadata
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

// Deterministic, position-dependent content spanning several 64 KiB windows so a
// wrong offset or a dropped partial window is visible in the transferred bytes.
$content = '';
for ($i = 0; $i < 200000; $i++) {
    $content .= chr(($i * 31 + 7) % 256);
}
// Rename the tempnam() file to a .bin path so the transferred file has a real
// extension for the Content-Type assertion (and nothing is left behind).
$data_file = tempnam(sys_get_temp_dir(), 'swoole_sendfile_');
rename($data_file, "$data_file.bin");
$data_file .= '.bin';
$empty_file = tempnam(sys_get_temp_dir(), 'swoole_sendfile_empty_');
file_put_contents($data_file, $content);
file_put_contents($empty_file, '');

$offset = 70000;
$length = 90000;
$partial_offset = 10000;
$partial_length = 65536 + 1234;

$configs = [
    [SWOOLE_BASE, true],
    [SWOOLE_PROCESS, true],
    [SWOOLE_BASE, false],
];

foreach ($configs as [$mode, $enable_coroutine]) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $content, $offset, $length, $partial_offset, $partial_length) {
        Coroutine\run(function () use ($pm, $content, $offset, $length, $partial_offset, $partial_length) {
            $client = new Client('127.0.0.1', $pm->getFreePort(), false);
            $client->set(['timeout' => 10]);
            Assert::true($client->connect());

            $fetch = function (string $path) use ($client) {
                $request = new Http2Request;
                $request->path = $path;
                Assert::greaterThan($client->send($request), 0);
                $response = $client->recv();
                Assert::notEmpty($response);
                return $response;
            };

            // Complete file.
            $response = $fetch('/complete');
            Assert::same($response->statusCode, 200);
            Assert::same($response->data, $content);
            Assert::same($response->headers['content-length'], (string) strlen($content));
            Assert::same($response->headers['content-type'], 'application/octet-stream');

            // Nonzero offset with a multi-window length.
            $response = $fetch('/offset');
            Assert::same($response->statusCode, 200);
            Assert::same($response->data, substr($content, $offset, $length));
            Assert::same($response->headers['content-length'], (string) $length);
            // Offset/length alone do not invent a Content-Range header.
            Assert::false(isset($response->headers['content-range']));

            // Length that ends inside a window exercises the final partial read.
            $response = $fetch('/partial');
            Assert::same($response->data, substr($content, $partial_offset, $partial_length));
            Assert::same($response->headers['content-length'], (string) $partial_length);

            // Empty file terminates with headers only and no DATA frame.
            $response = $fetch('/empty');
            Assert::same($response->statusCode, 200);
            Assert::same((string) $response->data, '');
            Assert::same($response->headers['content-length'], '0');

            // Trailers close a file response instead of a terminal DATA frame.
            $response = $fetch('/trailers');
            Assert::same($response->data, substr($content, 0, 100000));
            Assert::same($response->headers['content-length'], '100000');
            Assert::same($response->headers['grpc-status'], '0');
            Assert::same($response->headers['grpc-message'], 'done');

            // An application-supplied status and Content-Range are preserved.
            $response = $fetch('/custom-range');
            Assert::same($response->statusCode, 206);
            Assert::same($response->headers['content-range'], 'bytes 100-199/200000');
            Assert::same($response->data, substr($content, 100, 100));

            // The connection stays usable for a final ordinary request.
            $response = $fetch('/complete');
            Assert::same($response->data, $content);
        });
        $pm->kill();
    };
    $pm->childFunc = function () use (
        $pm,
        $mode,
        $enable_coroutine,
        $data_file,
        $empty_file,
        $offset,
        $length,
        $partial_offset,
        $partial_length
    ) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'enable_coroutine' => $enable_coroutine,
            'log_file' => '/dev/null',
            'open_http2_protocol' => true,
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function (Request $request, Response $response) use (
            $data_file,
            $empty_file,
            $offset,
            $length,
            $partial_offset,
            $partial_length
        ) {
            switch ($request->server['request_uri']) {
                case '/complete':
                    $response->sendfile($data_file);
                    break;
                case '/offset':
                    $response->sendfile($data_file, $offset, $length);
                    break;
                case '/partial':
                    $response->sendfile($data_file, $partial_offset, $partial_length);
                    break;
                case '/empty':
                    $response->sendfile($empty_file);
                    break;
                case '/trailers':
                    $response->header('trailer', 'grpc-status, grpc-message');
                    $response->trailer('grpc-status', '0');
                    $response->trailer('grpc-message', 'done');
                    $response->sendfile($data_file, 0, 100000);
                    break;
                case '/custom-range':
                    $response->status(206);
                    $response->header('content-range', 'bytes 100-199/200000');
                    $response->sendfile($data_file, 100, 100);
                    break;
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

unlink($data_file);
unlink($empty_file);
echo "DONE\n";
?>
--EXPECT--
DONE
