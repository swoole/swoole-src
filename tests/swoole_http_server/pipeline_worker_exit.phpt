--TEST--
swoole_http_server: a pipelined request held behind a killed worker does not keep the connection open
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$workerStarts = new Swoole\Atomic();
$heldSession = new Swoole\Atomic();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $workerStarts) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    fwrite($client, "GET /exit HTTP/1.1\r\nHost: localhost\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n");
    // The worker is killed while it handles /exit, so neither request is answered.
    $deadline = microtime(true) + 5;
    while ($workerStarts->get() === 1 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($workerStarts->get(), 2);
    fclose($client);
    $deadline = microtime(true) + 2;
    do {
        usleep(10000);
        $check = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
        fwrite($check, "GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        $state = substr(stream_get_contents($check), -6);
        fclose($check);
    } while ($state !== 'closed' && microtime(true) < $deadline);
    Assert::same($state, 'closed');

    // More than the 64 KiB receive buffer, which fills and stops reading until /slow is answered.
    $body = str_repeat('A', 100 * 1024);
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    stream_set_timeout($client, 5);
    fwrite(
        $client,
        "GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n" .
        "POST /next HTTP/1.1\r\nHost: localhost\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body
    );
    $response = '';
    while (!str_contains($response, 'next') && ($data = fread($client, 8192))) {
        $response .= $data;
    }
    $slow = strpos($response, 'slow');
    $nextResponse = strpos($response, 'next');
    Assert::true($slow !== false && $nextResponse !== false && $slow < $nextResponse);
    fclose($client);
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $workerStarts, $heldSession) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function () use ($pm, $workerStarts) {
        if ($workerStarts->add() === 1) {
            $pm->wakeup();
        }
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server, $heldSession) {
        $uri = $request->server['request_uri'];
        if ($uri === '/exit') {
            $heldSession->set($request->fd);
            Swoole\Coroutine::sleep(0.1);
            Swoole\Process::kill(getmypid(), SIGKILL);
        } elseif ($uri === '/held') {
            $response->end($server->exists($heldSession->get()) ? '  open' : 'closed');
        } elseif ($uri === '/slow') {
            Swoole\Coroutine::sleep(0.2);
            $response->end('slow');
        } else {
            $response->end(substr($uri, 1));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
