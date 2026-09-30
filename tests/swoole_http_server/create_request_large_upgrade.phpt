--TEST--
swoole_http_server: reject an oversized Upgrade value
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$suffix = ', websocket';
foreach ([64 * 1024 - 1, 64 * 1024, 128 * 1024] as $length) {
    $upgrade = str_repeat('x', $length - strlen($suffix)) . $suffix;
    $data = "GET / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Upgrade: {$upgrade}\r\n" .
        "Connection: Upgrade\r\n\r\n";
    $request = Request::create();
    $parsed = $request->parse($data);

    if ($length < 64 * 1024) {
        Assert::same($parsed, strlen($data));
        Assert::true($request->isCompleted());
        Assert::same($request->header['upgrade'], $upgrade);
    } else {
        Assert::true($parsed < strlen($data));
        Assert::false($request->isCompleted());
    }
}

$request = Request::create();
$first = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: " . str_repeat('x', 40 * 1024);
$second = str_repeat('x', 40 * 1024) . ", websocket\r\nConnection: Upgrade\r\n\r\n";
Assert::same($request->parse($first), strlen($first));
Assert::true($request->parse($second) < strlen($second));
Assert::false($request->isCompleted());

echo "DONE\n";
?>
--EXPECT--
DONE
