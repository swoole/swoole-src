--TEST--
swoole_http_server: static validators, malformed ranges, HEAD and URI paths in BASE and PROCESS
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$directory = sys_get_temp_dir() . '/swoole-static+%-' . getmypid();
mkdir($directory);
mkdir($directory . '/folder');
mkdir($directory . '/listing');
$files = [
    '/asset.txt' => '0123456789',
    '/empty.txt' => '',
    '/a+b.txt' => 'PLUS',
    '/a b.txt' => 'SPACE',
    '/folder/index.html' => 'INDEX-CONTENT',
    '/listing/entry.txt' => 'entry',
];
foreach ($files as $path => $content) {
    file_put_contents($directory . $path, $content);
    touch($directory . $path, 1730000000);
}
touch($directory . '/folder', 1600000000);
$ownerPid = getmypid();
register_shutdown_function(static function () use ($directory, $files, $ownerPid) {
    if (getmypid() !== $ownerPid) {
        return;
    }
    foreach ($files as $path => $_) {
        @unlink($directory . $path);
    }
    @rmdir($directory . '/folder');
    @rmdir($directory . '/listing');
    @rmdir($directory);
});

foreach ([SWOOLE_BASE => 'Asia/Shanghai', SWOOLE_PROCESS => 'America/New_York'] as $mode => $timezone) {
    $pm = new ProcessManager;
    $pm->parentFunc = static function () use ($pm) {
        Swoole\Coroutine\run(static function () use ($pm) {
            foreach ([false, true] as $http2) {
                $fetch = static function ($path, $headers = [], $method = 'GET') use ($pm, $http2) {
                    return httpRequest("http://127.0.0.1:{$pm->getFreePort()}{$path}", [
                        'http2' => $http2, 'headers' => $headers, 'method' => $method, 'redirect' => 0,
                    ]);
                };
                $response = $fetch('/asset.txt');
                Assert::same($response['statusCode'], 200);
                Assert::same($response['body'], '0123456789');
                Assert::true(str_ends_with($response['headers']['date'], ' GMT'));
                $etag = $response['headers']['etag'];
                $date = $response['headers']['last-modified'];
                Assert::same($date, gmdate(DATE_RFC7231, 1730000000));
                foreach (['bytes=word', 'bytes=0-1,word', 'bytes=0-1,4-5,word', 'bytes=0-1,',
                          'bytes=10-20', 'bytes=8-2', 'bytes=-0'] as $range) {
                    $response = $fetch('/asset.txt', ['range' => $range]);
                    Assert::same($response['statusCode'], 416);
                    Assert::isEmpty($response['body']);
                    Assert::same($response['headers']['content-range'], 'bytes */10');
                    Assert::same($response['headers']['content-length'], '0');
                }
                $response = $fetch('/asset.txt', ['range' => 'bytes=0-1,4-5']);
                Assert::same($response['statusCode'], 206);
                Assert::same((int) $response['headers']['content-length'], strlen($response['body']));
                Assert::contains($response['body'], "\r\n\r\n01\r\n");
                Assert::contains($response['body'], "\r\n\r\n45\r\n");
                foreach (['invalid', '"other"', 'W/' . $etag] as $validator) {
                    $response = $fetch('/asset.txt', ['range' => 'bytes=0-1', 'if-range' => $validator]);
                    Assert::same($response['statusCode'], 200);
                    Assert::same($response['body'], '0123456789');
                }
                foreach ([$date, $etag] as $validator) {
                    $response = $fetch('/asset.txt', ['range' => 'bytes=0-1', 'if-range' => $validator]);
                    Assert::same($response['statusCode'], 206);
                    Assert::same($response['body'], '01');
                    Assert::same($response['headers']['content-range'], 'bytes 0-1/10');
                }
                foreach (['bytes=0-9,0-9', 'bytes=' . implode(',', array_fill(0, 32, '0-0'))] as $range) {
                    $response = $fetch('/asset.txt', ['range' => $range]);
                    Assert::same($response['statusCode'], 200);
                    Assert::same($response['body'], '0123456789');
                }
                foreach ([
                    ['if-modified-since' => $date],
                    ['if-none-match' => '*'],
                    ['if-none-match' => 'W/' . $etag],
                    ['if-none-match' => '"other", ' . $etag],
                ] as $headers) {
                    $response = $fetch('/asset.txt', $headers);
                    Assert::same($response['statusCode'], 304);
                    Assert::isEmpty($response['body']);
                    Assert::same($response['headers']['etag'], $etag);
                }
                foreach ([
                    ['if-match' => '"other"'],
                    ['if-match' => 'W/' . $etag],
                    ['if-unmodified-since' => gmdate(DATE_RFC7231, 1729996400)],
                ] as $headers) {
                    Assert::same($fetch('/asset.txt', $headers)['statusCode'], 412);
                }
                Assert::same($fetch('/asset.txt', ['if-none-match' => '"other"', 'if-modified-since' => $date])['statusCode'], 200);
                Assert::same($fetch('/asset.txt', ['if-match' => $etag, 'if-unmodified-since' => gmdate(DATE_RFC7231, 1600000000)])['statusCode'], 200);
                Assert::same($fetch('/asset.txt', ['if-modified-since' => gmdate(DATE_RFC7231, 1729996400)])['statusCode'], 200);
                $response = $fetch('/folder/', ['if-modified-since' => gmdate(DATE_RFC7231, 1600000000)]);
                Assert::same($response['statusCode'], 200);
                Assert::same($response['body'], 'INDEX-CONTENT');
                Assert::same($response['headers']['last-modified'], $date);
                $response = $fetch('/folder?query=1');
                Assert::same($response['statusCode'], 301);
                Assert::same($response['headers']['location'], '/folder/?query=1');
                Assert::same($fetch('/a+b.txt')['body'], 'PLUS');
                Assert::same($fetch('/a%20b.txt')['body'], 'SPACE');
                foreach (['/asset.txt%00.jpg', '/asset.txt%', '/asset.txt%xy'] as $path) {
                    Assert::same($fetch($path)['statusCode'], 400);
                }
                foreach (['/asset.txt' => 200, '/folder/' => 200, '/listing/' => 200, '/missing.txt' => 404] as $path => $status) {
                    $get = $fetch($path);
                    $head = $fetch($path, [], 'HEAD');
                    Assert::same($head['statusCode'], $status);
                    Assert::isEmpty($head['body']);
                    Assert::same($head['headers']['content-length'], $get['headers']['content-length']);
                }
                Assert::isEmpty($fetch('/empty.txt')['body']);
                foreach (['DELETE', 'OPTIONS', 'POST'] as $method) {
                    Assert::same($fetch('/asset.txt', [], $method)['body'], 'DYNAMIC');
                }
            }
            // Read the raw transport to prove completion, not just a Connection header.
            foreach ([['HEAD', '/missing.txt', ''], ['HEAD', '/listing/', ''],
                      ['GET', '/asset.txt', 'If-None-Match: *' . "\r\n"]] as [$method, $path, $headers]) {
                $socket = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                Assert::true($socket->connect('127.0.0.1', $pm->getFreePort(), 3));
                $socket->send("{$method} {$path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{$headers}\r\n");
                $raw = '';
                while (($chunk = $socket->recv(3)) !== '') {
                    Assert::notEq($chunk, false);
                    if ($chunk === false) {
                        break;
                    }
                    $raw .= $chunk;
                }
                Assert::same(explode("\r\n\r\n", $raw, 2)[1], '');
                $socket->close();
            }
        });
        $pm->kill();
    };
    $pm->childFunc = static function () use ($pm, $directory, $mode, $timezone) {
        putenv('TZ=' . $timezone);
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1, 'reactor_num' => 1, 'log_file' => '/dev/null',
            'enable_static_handler' => true, 'document_root' => $directory,
            'static_handler_locations' => ['/'], 'http_index_files' => ['missing.html', 'index.html'],
            'http_autoindex' => true, 'open_http2_protocol' => true, 'http_compression' => false,
        ]);
        $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
        $server->on('Request', static function ($request, $response) { $response->end('DYNAMIC'); });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
