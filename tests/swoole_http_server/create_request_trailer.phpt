--TEST--
swoole_http_server: ignore request trailers across every parse boundary
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$header = "POST / HTTP/1.1\r\nHost: localhost\r\n" .
    "Content-Type: application/x-www-form-urlencoded\r\n" .
    "Cookie: initial=yes\r\nX-Check: header\r\nTransfer-Encoding: chunked\r\n\r\n";
$body = 'field=value';
$chunks = "5\r\nfield\r\n6\r\n=value\r\n0\r\n";
$trailer = "Content-Type: text/plain\r\nCookie: extra=no\r\nUpgrade: websocket\r\nAccept-Encoding: gzip\r\n" .
    "X-Check: first\r\nx-check: second\r\nX-Empty:\r\n\r\n";
$data = $header . $chunks . $trailer;

function check_request(Request $request): void
{
    global $body, $data;
    Assert::true($request->isCompleted());
    Assert::false(property_exists($request, 'trailer'));
    Assert::same($request->header['content-type'], 'application/x-www-form-urlencoded');
    Assert::same($request->header['x-check'], 'header');
    Assert::false(isset($request->header['x-empty']));
    Assert::false(isset($request->header['upgrade']));
    Assert::false(isset($request->header['accept-encoding']));
    Assert::same($request->cookie, ['initial' => 'yes']);
    Assert::same($request->post, ['field' => 'value']);
    Assert::same($request->rawContent(), $body);
    Assert::same($request->getData(), $data);
}

for ($split = 1; $split < strlen($data); $split++) {
    $request = Request::create();
    Assert::same($request->parse(substr($data, 0, $split)), $split);
    Assert::false($request->isCompleted());
    Assert::same($request->parse(substr($data, $split)), strlen($data) - $split);
    check_request($request);
}

$request = Request::create();
foreach (str_split($data) as $byte) {
    Assert::same($request->parse($byte), 1);
}
check_request($request);

// Incomplete and empty trailer fields are ignored as well.
$request = Request::create();
$prefix = $header . $chunks . 'X-Check: par';
Assert::same($request->parse($prefix), strlen($prefix));
Assert::false(property_exists($request, 'trailer'));
Assert::false($request->isCompleted());
$suffix = "tial\r\nX-Empty:\r\n\r\n";
Assert::same($request->parse($suffix), strlen($suffix));
Assert::false(property_exists($request, 'trailer'));
Assert::true($request->isCompleted());

foreach ([$header . $chunks . "\r\n", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"] as $data) {
    $request = Request::create();
    Assert::same($request->parse($data), strlen($data));
    Assert::true($request->isCompleted());
    Assert::false(property_exists($request, 'trailer'));
}
echo "DONE\n";
?>
--EXPECT--
DONE
