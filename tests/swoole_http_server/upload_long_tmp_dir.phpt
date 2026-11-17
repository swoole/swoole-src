--TEST--
swoole_http_server: upload temporary directories longer than 256 bytes are preserved
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$base = sys_get_temp_dir() . '/swoole-upload-long-' . getmypid();
$dir = $base;
$directories = [];
$request = null;
try {
    for ($i = 0; $i < 6; $i++) {
        Assert::true(mkdir($dir));
        $directories[] = $dir;
        if ($i < 5) {
            $dir .= '/' . str_repeat('x', 60);
        }
    }
    Assert::greaterThan(strlen($dir), 256);
    $body = "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
        . "Content-Type: text/plain\r\n\r\npayload\r\n--test--\r\n";
    $data = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=test\r\n"
        . 'Content-Length: ' . strlen($body) . "\r\n\r\n" . $body;
    $request = Swoole\Http\Request::create(['parse_files' => true, 'upload_tmp_dir' => $dir]);
    foreach (str_split($data, 13) as $chunk) {
        Assert::same($request->parse($chunk), strlen($chunk));
    }
    Assert::true($request->isCompleted());
    $file = $request->files['file'];
    Assert::same($file['error'], UPLOAD_ERR_OK);
    Assert::same(dirname($file['tmp_name']), $dir);
    Assert::same(file_get_contents($file['tmp_name']), 'payload');
    Assert::true(is_uploaded_file($file['tmp_name']));
    unset($request);
    Assert::false(file_exists($file['tmp_name']));
    Assert::false(is_uploaded_file($file['tmp_name']));
} finally {
    unset($request);
    foreach (array_reverse($directories) as $directory) {
        Assert::true(rmdir($directory));
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
