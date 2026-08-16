--TEST--
swoole_http_server: parse request
--SKIPIF--
<?php

require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$data = "GET /index.html?hello=world&test=2123 HTTP/1.1\r\n";
$data .= "Host: 127.0.0.1\r\n";
$data .= "Connection: keep-alive\r\n";
$data .= "Pragma: no-cache\r\n";
$data .= "Cache-Control: no-cache\r\n";
$data .= "Upgrade-Insecure-Requests: \r\n";
$data .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36\r\n";
$data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n";
$data .= "Accept-Encoding: gzip, deflate, br\r\n";
$data .= "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6\r\n";
$data .= "Cookie: env=pretest; phpsessid=fcccs2af8673a2f343a61a96551c8523d79ea; username=hantianfeng\r\n";

$req = Request::create();
Assert::count($req->header, 0);
Assert::false($req->isCompleted());

Assert::eq($req->parse($data . "\r\n"), strlen($data) + 2);

Assert::true($req->isCompleted());
Assert::false($req->parse('error data'));

Assert::eq("GET", $req->getMethod());

Assert::greaterThan(count($req->header), 4);
Assert::eq(count($req->cookie), 3);

Assert::eq($req->getData(), $data."\r\n");

$req2 = Request::create(['parse_cookie' => false]);
Assert::eq($req2->parse($data . "\r\n"), strlen($data) + 2);
Assert::null($req2->cookie);

$data = "POST /index.html?hello=world&test=2123 HTTP/1.1\r\n";
$data .= "Host: 127.0.0.1\r\n";
$data .= "Connection: keep-alive\r\n";
$data .= "Pragma: no-cache\r\n";
$data .= "Cache-Control: no-cache\r\n";
$data .= "Upgrade-Insecure-Requests: \r\n";
$data .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36\r\n";
$data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n";
$data .= "Accept-Encoding: gzip, deflate, br\r\n";
$data .= "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,ja;q=0.6\r\n";
$data .= "Cookie: env=pretest; phpsessid=fcccs2af8673a2f343a61a96551c8523d79ea; username=hantianfeng\r\n";

$req3 = Request::create();
$req3->parse($data);
Assert::eq("POST", $req3->getMethod());

$body = 'first=one&second=two';
$headers = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
$headers .= 'Content-Length: ' . strlen($body) . "\r\n\r\n";
$request = Request::create();
Assert::same($request->parse($headers), strlen($headers));
Assert::false($request->isCompleted());
foreach (str_split($body, 2) as $chunk) {
    Assert::same($request->parse($chunk), strlen($chunk));
}
Assert::true($request->isCompleted());
Assert::same($request->post, ['first' => 'one', 'second' => 'two']);

$body = 'first=one&second=two';
$duplicate = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$duplicate .= "Content-Type: multipart/form-data; boundary=ignored\r\n";
$duplicate .= "Content-Type: application/x-www-form-urlencoded\r\n";
$duplicate .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
$request = Request::create();
Assert::same($request->parse($duplicate), strlen($duplicate));
Assert::true($request->isCompleted());
Assert::same($request->post, ['first' => 'one', 'second' => 'two']);

$empty = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$empty .= "Content-Type: multipart/form-data; boundary=empty\r\n";
$empty .= "Content-Length: 0\r\n\r\n";
$request = Request::create();
Assert::same($request->parse($empty), strlen($empty));
Assert::true($request->isCompleted());
Assert::null($request->post);
Assert::null($request->files);

$body = "--incomplete\r\nContent-Disposition: form-data; name=\"unfinished";
$incomplete = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$incomplete .= "Content-Type: multipart/form-data; boundary=incomplete\r\n";
$incomplete .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
$request = Request::create();
Assert::same($request->parse($incomplete), strlen($incomplete));
Assert::false($request->isCompleted());
Assert::null($request->post);
Assert::null($request->files);

$boundary = 'fragmented-boundary';
$body = "--{$boundary}\r\n";
$body .= "Content-Type: text/plain\r\n";
$body .= "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\n";
$body .= "file-value\r\n";
$body .= "--{$boundary}\r\n";
$body .= "Content-Disposition: form-data; name=\"field\"\r\n\r\n";
$body .= "field-value\r\n";
$body .= "--{$boundary}--\r\n";
$duplicate = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$duplicate .= "Content-Type: application/x-www-form-urlencoded\r\n";
$duplicate .= "Content-Type: multipart/form-data; boundary={$boundary}\r\n";
$duplicate .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
// Split one part-header field name and one part-header value across parse calls.
$fieldSplit = strpos($duplicate, 'Content-Disposition: form-data; name="file"') + strlen('Content-Dis');
$valueSplit = strpos($duplicate, 'name="field"') + strlen('name="fi');
$request = Request::create();
Assert::same($request->parse(substr($duplicate, 0, $fieldSplit)), $fieldSplit);
$length = $valueSplit - $fieldSplit;
Assert::same($request->parse(substr($duplicate, $fieldSplit, $length)), $length);
Assert::same($request->parse(substr($duplicate, $valueSplit)), strlen($duplicate) - $valueSplit);
Assert::true($request->isCompleted());
Assert::same($request->post['field'], 'field-value');
Assert::same($request->files['file']['name'], 'test.txt');
Assert::same($request->files['file']['type'], 'text/plain');
Assert::same(file_get_contents($request->files['file']['tmp_name']), 'file-value');

?>
--EXPECT--
