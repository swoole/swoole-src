--TEST--
swoole_http_server: preserve original Cookie headers when parsing cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([true, false] as $parseCookie) {
    $request = Swoole\Http\Request::create(['parse_cookie' => $parseCookie]);
    $raw = "GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session=a%2Bb%20c; zero=0\r\n"
        . "cookie: other=%3B%00\r\n\r\n";
    Assert::same($request->parse($raw), strlen($raw));
    Assert::same($request->header['cookie'], ['session=a%2Bb%20c; zero=0', 'other=%3B%00']);
    if ($parseCookie) {
        Assert::same($request->cookie, ['session' => 'a+b c', 'zero' => '0', 'other' => ";\0"]);
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
