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

$data1 = substr($data, 0, rand(100, 600));
$data2 = substr($data, strlen($data1));

Assert::eq($req->parse($data1), strlen($data1));
Assert::false($req->isCompleted());
Assert::eq($req->parse($data2), strlen($data2));
Assert::false($req->isCompleted());
Assert::eq($req->parse("\r\n"), 2);

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

$fragmented = "POST /upload HTTP/1.1\r\n";
$fragmented .= "Host: 127.0.0.1\r\n";
$fragmented .= "Content-Type: application/x-www-form-urlencoded\r\n";
$fragmented .= "Authorization: Bearer fragmented\r\n";
$fragmented .= "X-Custom-Header: custom value\r\n";
$fragmented .= "Upgrade-Insecure-Requests: \r\n";
$fragmented .= "User-Agent: fragmented-agent\r\n";
$fragmented .= "Cookie: first=one; second=two\r\n";
$fragmented .= "Content-Length: 0\r\n\r\n";

$assertFragmented = static function (Request $request): void {
    Assert::true($request->isCompleted());
    Assert::same($request->header['host'], '127.0.0.1');
    Assert::same($request->header['content-type'], 'application/x-www-form-urlencoded');
    Assert::same($request->header['authorization'], 'Bearer fragmented');
    Assert::same($request->header['x-custom-header'], 'custom value');
    Assert::same($request->header['upgrade-insecure-requests'], '');
    Assert::same($request->header['user-agent'], 'fragmented-agent');
    Assert::same($request->cookie, ['first' => 'one', 'second' => 'two']);
};

for ($split = 1; $split < strlen($fragmented); $split++) {
    $request = Request::create();
    Assert::same($request->parse(substr($fragmented, 0, $split)), $split);
    Assert::same($request->parse(substr($fragmented, $split)), strlen($fragmented) - $split);
    $assertFragmented($request);
}

$request = Request::create();
foreach (str_split($fragmented) as $byte) {
    Assert::same($request->parse($byte), 1);
}
$assertFragmented($request);

$duplicate = "POST / HTTP/1.1\r\nHost: localhost\r\n";
$duplicate .= "Content-Type: application/x-www-form-urlencoded\r\n";
$duplicate .= "Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
$request = Request::create();
Assert::notSame($request->parse($duplicate), strlen($duplicate));
Assert::false($request->isCompleted());

$oversizedPrefix = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: " . str_repeat('A', 32768);
$oversizedSuffix = str_repeat('A', 32768) . "\r\n\r\n";
$request = Request::create();
Assert::same($request->parse($oversizedPrefix), strlen($oversizedPrefix));
Assert::notSame($request->parse($oversizedSuffix), strlen($oversizedSuffix));
Assert::false($request->isCompleted());

?>
--EXPECT--
