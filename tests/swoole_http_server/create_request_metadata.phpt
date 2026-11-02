--TEST--
swoole_http_server: preserve request paths and duplicate header keys across parse boundaries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$path = '/dir.name/a%2Fb+c.json';
$data = "GET $path?items[]=one&items[]=two HTTP/1.1\r\nHost: localhost\r\n" .
    "X-Request-Id: first\r\nx-request-id: second\r\nX-REQUEST-ID: third\r\n" .
    "123: first\r\n123: second\r\n0123: leading-zero\r\n-1: negative\r\n\r\n";
for ($split = 1; $split < strlen($data); $split++) {
    $request = Swoole\Http\Request::create();
    Assert::same($request->parse(substr($data, 0, $split)), $split);
    Assert::same($request->parse(substr($data, $split)), strlen($data) - $split);
    Assert::true($request->isCompleted());
    Assert::same($request->server['request_uri'], $path);
    Assert::same($request->server['path_info'], '/dir.name/a/b c.json');
    Assert::same($request->get, ['items' => ['one', 'two']]);
    Assert::same($request->header['x-request-id'], ['first', 'second', 'third']);
    Assert::same($request->header[123], ['first', 'second']);
    Assert::same($request->header['0123'], 'leading-zero');
    Assert::same($request->header[-1], 'negative');
    $server = $request->server;
    $request->server['request_uri'] = 'changed';
    unset($request);
    Assert::same($server['request_uri'], $path);
}
echo "DONE\n";
?>
--EXPECT--
DONE
