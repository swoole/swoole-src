--TEST--
swoole_http_server: release multipart state after fragmented nested uploads
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$body = "--test\r\nContent-Disposition: form-data; name=\"before\"\r\n\r\nfirst\r\n";
foreach (['one' => 'first', 'two' => 'second', 'one-again' => 'third'] as $key => $content) {
    $field = $key === 'one-again' ? 'one' : $key;
    $body .= "--test\r\nContent-Disposition: form-data; name=\"files[$field]\"; filename=\"$content.txt\"\r\n" .
        "Content-Type: text/plain\r\n\r\n$content\r\n";
}
$body .= "--test\r\nContent-Disposition: form-data; name=\"after\"\r\n\r\nlast\r\n--test--\r\n";
$data = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=test\r\n" .
    'Content-Length: ' . strlen($body) . "\r\n\r\n$body";
$request = Swoole\Http\Request::create(['parse_files' => true]);
foreach (str_split($data, 13) as $chunk) {
    Assert::same($request->parse($chunk), strlen($chunk));
}
Assert::true($request->isCompleted());
Assert::same($request->post, ['before' => 'first', 'after' => 'last']);
Assert::same($request->files['files']['name'], ['one' => 'third.txt', 'two' => 'second.txt']);
Assert::same($request->files['files']['type'], ['one' => 'text/plain', 'two' => 'text/plain']);
Assert::same($request->files['files']['error'], ['one' => UPLOAD_ERR_OK, 'two' => UPLOAD_ERR_OK]);
Assert::same(file_get_contents($request->files['files']['tmp_name']['one']), 'third');
Assert::same(file_get_contents($request->files['files']['tmp_name']['two']), 'second');
Assert::same($request->rawContent(), $body);
$paths = $request->tmpfiles;
Assert::count($paths, 3);
foreach ($paths as $path) {
    Assert::true(is_uploaded_file($path));
}
unset($request);
foreach ($paths as $path) {
    Assert::false(file_exists($path));
    Assert::false(is_uploaded_file($path));
}
echo "DONE\n";
?>
--EXPECT--
DONE
