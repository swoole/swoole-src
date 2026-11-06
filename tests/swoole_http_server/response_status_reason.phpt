--TEST--
swoole_http_server: retain, replace and reset custom status reasons
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        foreach (['custom' => '201 ' . str_repeat('Custom Reason ', 16),
            'reset' => '200 OK', 'empty' => '202 Accepted',
            'replace' => '203 ' . str_repeat('Replacement ', 16)] as $path => $status) {
            $socket = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
            stream_set_timeout($socket, 3);
            $request = "GET /$path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            Assert::same(fwrite($socket, $request), strlen($request));
            $response = stream_get_contents($socket);
            Assert::false(stream_get_meta_data($socket)['timed_out']);
            fclose($socket);
            Assert::same(explode("\r\n", $response, 2)[0], 'HTTP/1.1 ' . $status);
            Assert::same(explode("\r\n\r\n", $response, 2)[1], 'OK');
        }
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null', 'http_compression' => false]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        $reason = str_repeat('Custom Reason ', 16);
        Assert::true($response->status(201, $reason));
        // Mutating and releasing the caller's string must preserve the stored reason.
        $reason[0] = 'X';
        unset($reason);
        if ($request->server['request_uri'] === '/reset') {
            Assert::true($response->status(200));
        } elseif ($request->server['request_uri'] === '/empty') {
            Assert::true($response->status(202, ''));
        } elseif ($request->server['request_uri'] === '/replace') {
            // Replacing a custom reason must release the previous reference.
            Assert::true($response->status(201, str_repeat('Replacement ', 16)));
            Assert::true($response->status(203, str_repeat('Replacement ', 16)));
        }
        Assert::true($response->end('OK'));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
