--TEST--
swoole_http_server: empty trailers preserve chunk termination and keepalive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    stream_set_timeout($client, 5);
    try {
        $cases = [
            'none' => '',
            'null' => '',
            'unset' => '',
            'empty_array' => '',
            'null_property' => '',
            'numeric_key' => '',
            'mixed' => "x-kept: value\r\n",
        ];
        foreach ($cases as $case => $trailers) {
            fwrite($client, "GET /$case HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
            $headers = stream_get_line($client, 65536, "\r\n\r\n");
            Assert::contains($headers, 'Transfer-Encoding: chunked', $case);
            $expected = "4\r\nbody\r\n4\r\ntail\r\n0\r\n" . $trailers . "\r\n";
            $body = '';
            while (strlen($body) < strlen($expected)) {
                $chunk = fread($client, strlen($expected) - strlen($body));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $body .= $chunk;
            }
            Assert::same($body, $expected, $case);
            if ($body !== $expected) {
                break;
            }
        }
    } finally {
        fclose($client);
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $case = substr($request->server['request_uri'], 1);
        if ($case !== 'none') {
            Assert::true($response->trailer('x-test', null));
            switch ($case) {
                case 'unset':
                    unset($response->trailer['x-test']);
                    break;
                case 'empty_array':
                    $response->trailer = [];
                    break;
                case 'null_property':
                    $response->trailer = null;
                    break;
                case 'numeric_key':
                    $response->trailer = [123 => 'ignored'];
                    break;
                case 'mixed':
                    Assert::true($response->trailer('x-kept', 'value'));
                    break;
            }
        }
        Assert::true($response->write('body'));
        Assert::true($response->end('tail'));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
