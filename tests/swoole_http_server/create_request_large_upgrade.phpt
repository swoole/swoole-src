--TEST--
swoole_http_server: handle an oversized Upgrade value safely
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;

$upgrade = str_repeat('x', 128 * 1024) . ', websocket';
$data = "GET / HTTP/1.1\r\n" .
    "Host: localhost\r\n" .
    "Upgrade: {$upgrade}\r\n" .
    "Connection: Upgrade\r\n\r\n";
$request = Request::create();

Assert::same($request->parse($data), strlen($data));
Assert::true($request->isCompleted());
Assert::same($request->header['upgrade'], $upgrade);

echo "DONE\n";
?>
--EXPECT--
DONE
