--TEST--
swoole_http_server: hold a pipelined request while the connection is paused
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        $seconds = [
            "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "POST /second HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata",
        ];
        // A large first response is still being sent when its handler returns.
        foreach (['/first', '/first?large=1'] as $first) {
            foreach ($seconds as $second) {
                $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
                stream_set_timeout($client, 2);
                fwrite($client, "GET {$first} HTTP/1.1\r\nHost: localhost\r\n\r\n" . $second);

                $response = '';
                while (!str_ends_with($response, 'resumed') && !str_ends_with($response, 'paused') && !feof($client)) {
                    $data = fread($client, 65536);
                    if (!$data) {
                        break;
                    }
                    $response .= $data;
                }
                fclose($client);
                Assert::same(substr_count($response, 'HTTP/1.1 200 OK'), 2);
                Assert::true(str_ends_with($response, 'resumed'));
            }
        }
        $pm->kill();
        echo "DONE\n";
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'log_file'   => '/dev/null',
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $resumed = [];
        $server->on('request', function ($request, $response) use ($server, &$resumed) {
            $fd = $request->fd;
            if ($request->server['request_uri'] === '/first') {
                $server->pause($fd);
                Swoole\Timer::after(300, function () use ($server, $fd, &$resumed) {
                    $resumed[$fd] = true;
                    $server->resume($fd);
                });
                $response->end(isset($request->get['large']) ? str_repeat('a', 4 * 1024 * 1024) : 'first');
            } else {
                $response->end(isset($resumed[$fd]) ? 'resumed' : 'paused');
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
DONE
DONE
