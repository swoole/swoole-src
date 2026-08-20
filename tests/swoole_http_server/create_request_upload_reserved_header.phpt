--TEST--
swoole_http_server: create request upload reserved header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
file_put_contents($probe, 'probe');
$content = 'direct upload body';
$boundary = '------------------------d3f990cdce762596';
$body = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Swoole-Upload-File: ' . $probe,
    'Content-Type: text/plain',
    '',
    $content,
    '--' . $boundary . '--',
    '',
]);
$data = implode("\r\n", [
    'POST / HTTP/1.1',
    'Host: 127.0.0.1',
    'Connection: close',
    'Content-Type: multipart/form-data; boundary=' . $boundary,
    'Content-Length: ' . strlen($body),
    '',
    $body,
]);

$req = Request::create();
Assert::same($req->parse($data), strlen($data));
Assert::true($req->isCompleted());
Assert::true(isset($req->files['file']));
Assert::same(md5_file($req->files['file']['tmp_name']), md5($content));
Assert::false($req->files['file']['tmp_name'] === $probe);
Assert::false(is_uploaded_file($probe));
unset($req);
Assert::true(file_exists($probe));
unlink($probe);
?>
--EXPECT--
