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

?>
--EXPECT--
