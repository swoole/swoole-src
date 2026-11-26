--TEST--
swoole_http_server: Request::parse keeps only the consumed request data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$next = "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
$body = 'field=value';
$fixed = "POST /fixed HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n"
    . 'Content-Length: ' . strlen($body) . "\r\n\r\n" . $body;
$chunked = "POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
    . "2\r\nhe\r\n3\r\nllo\r\n0\r\nX-Trace: done\r\n\r\n";

foreach ([[$fixed, $body], [$chunked, 'hello'], [$next, '']] as [$raw, $content]) {
    $request = Request::create();
    $input = $raw . $next;
    $consumed = $request->parse($input);
    Assert::same($consumed, strlen($raw));
    Assert::true($request->isCompleted());
    Assert::same($request->getContent(), $content);
    Assert::same($request->getData(), $raw);

    $following = Request::create();
    Assert::same($following->parse(substr($input, $consumed)), strlen($next));
    Assert::same($following->getData(), $next);
}

$prefix = substr($fixed, 0, -2);
$request = Request::create();
Assert::same($request->parse($prefix), strlen($prefix));
Assert::false($request->isCompleted());
$saved = $request->getData();
Assert::same($request->parse(substr($fixed, -2) . $next), 2);
Assert::true($request->isCompleted());
Assert::same($request->getData(), $fixed);
Assert::same($request->getContent(), $body);
Assert::same($request->post, ['field' => 'value']);
Assert::same($saved, $prefix);
echo "DONE\n";
?>
--EXPECT--
DONE
