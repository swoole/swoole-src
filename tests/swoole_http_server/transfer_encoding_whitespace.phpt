--TEST--
swoole_http_server: accept optional whitespace after chunked transfer coding
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function chunkedRequestWithOws(string $ows): string
{
    return "POST / HTTP/1.1\r\n"
        . "Host: localhost\r\n"
        . "Transfer-Encoding: chunked{$ows}\r\n"
        . "Connection: close\r\n\r\n"
        . "5\r\nhello\r\n0\r\n\r\n";
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        foreach (["\t", " \t "] as $ows) {
            $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $error, 2);
            Assert::notSame($client, false);
            try {
                stream_set_timeout($client, 2);
                $request = chunkedRequestWithOws($ows);
                Assert::same(fwrite($client, $request), strlen($request));
                $response = explode("\r\n\r\n", stream_get_contents($client), 2);
                Assert::startsWith($response[0], 'HTTP/1.1 200 OK');
                Assert::same($response[1] ?? null, 'hello');
            } finally {
                fclose($client);
            }
        }
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
        $server->on($mode === SWOOLE_PROCESS ? 'Start' : 'WorkerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('request', function ($request, $response) {
            $response->end($request->rawContent());
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

// Split at the whitespace after the coding to exercise the llhttp resume state.
$packet = chunkedRequestWithOws("\t");
$offset = strpos($packet, "\t");
$request = Swoole\Http\Request::create();
Assert::same($request->parse(substr($packet, 0, $offset)), $offset);
Assert::same($request->parse(substr($packet, $offset)), strlen($packet) - $offset);
Assert::true($request->isCompleted());
Assert::same($request->rawContent(), 'hello');

echo "DONE\n";
?>
--EXPECT--
DONE
