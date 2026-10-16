--TEST--
swoole_http_server: bound fragmented multipart headers and close unfinished uploads
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine::set(['log_level' => SWOOLE_LOG_NONE]);

function parse_multipart_parts(array $chunks, string $body, array $options = []): Swoole\Http\Request
{
    $request = Swoole\Http\Request::create($options);
    $head    = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=review\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
    Assert::same($request->parse($head), strlen($head));
    foreach ($chunks as $chunk) {
        if ($request->parse($chunk) !== strlen($chunk)) {
            break;
        }
    }
    return $request;
}

// A fragmented name or value must be rejected before the next fragment is accumulated.
foreach ([str_repeat('X', 65537) . ': value', 'X-Test: ' . str_repeat('a', 65537)] as $header) {
    $body    = "--review\r\n{$header}\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--review--\r\n";
    $request = parse_multipart_parts(str_split($body, 8192), $body);
    Assert::false($request->isCompleted());
    unset($request);
}

// The combined name/value limit itself is accepted.
$body = "--review\r\nX-Test: " . str_repeat('a', 65530)
    . "\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--review--\r\n";
$request = parse_multipart_parts(str_split($body, 8192), $body);
Assert::true($request->isCompleted());
Assert::same($request->post['field'], 'value');
unset($request);

// Clear the parser before unlinking an unfinished file, including on Windows.
$body      = "--review\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nunfinished";
$directory = sys_get_temp_dir() . '/swoole-multipart-' . getmypid();
Assert::true(mkdir($directory));
try {
    foreach ([[], ['upload_tmp_dir' => $directory]] as $options) {
        $request = parse_multipart_parts([$body], $body . "\r\n--review--\r\n", $options);
        Assert::false($request->isCompleted());
        Assert::count($request->tmpfiles, 1);
        $path = $request->tmpfiles[0];
        Assert::same(realpath(dirname($path)), realpath($options['upload_tmp_dir'] ?? sys_get_temp_dir()));
        Assert::true(file_exists($path));
        unset($request);
        Assert::false(file_exists($path));
    }
} finally {
    rmdir($directory);
}
?>
--EXPECT--
