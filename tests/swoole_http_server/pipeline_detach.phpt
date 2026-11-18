--TEST--
swoole_http_server: Response::detach() hands the connection's response order to the application
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function read_until($client, array $parts): string
{
    $response = '';
    while (array_filter($parts, fn($part) => !str_contains($response, $part)) && ($data = fread($client, 8192))) {
        $response .= $data;
    }
    return $response;
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $mode) {
        // Response::create() from a task worker needs the shared session table of PROCESS mode.
        foreach ($mode === SWOOLE_PROCESS ? ['/raw', '/task'] : ['/raw'] as $path) {
            $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
            stream_set_timeout($client, 2);
            fwrite(
                $client,
                "GET {$path} HTTP/1.1\r\nHost: localhost\r\n\r\n" .
                "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n" .
                "GET /third HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            $response = read_until($client, ['detached', 'second', 'third']);
            Assert::contains($response, 'detached');
            Assert::contains($response, 'second');
            Assert::contains($response, 'third');
            fwrite($client, "GET /fourth HTTP/1.1\r\nHost: localhost\r\n\r\n");
            Assert::contains(read_until($client, ['fourth']), 'fourth');
            fclose($client);
        }
        $pm->kill();
        echo "DONE\n";
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'task_worker_num' => 1,
            'log_file' => '/dev/null',
        ]);
        $server->on('workerStart', function (Swoole\Server $server, int $workerId) use ($pm) {
            if ($workerId === 0) {
                $pm->wakeup();
            }
        });
        $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server) {
            $uri = $request->server['request_uri'];
            if ($uri === '/raw') {
                Assert::true($response->detach());
                $fd = $request->fd;
                Swoole\Timer::after(100, function () use ($server, $fd) {
                    $server->send($fd, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndetached");
                });
            } elseif ($uri === '/task') {
                Assert::true($response->detach());
                $server->task($request->fd);
            } elseif ($uri === '/second') {
                Swoole\Coroutine::sleep(0.2);
                $response->end('second');
            } else {
                $response->end(substr($uri, 1));
            }
        });
        $server->on('task', function (Swoole\Server $server, int $taskId, int $workerId, int $fd) {
            usleep(100000);
            Swoole\Http\Response::create($server, $fd)->end('detached');
        });
        $server->on('finish', function () {
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
