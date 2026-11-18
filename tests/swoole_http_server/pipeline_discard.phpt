--TEST--
swoole_http_server: a request discarded by dispatch_func does not hold the next request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function read_kept($client): string
{
    $response = '';
    while (!str_contains($response, 'kept') && ($data = fread($client, 8192))) {
        $response .= $data;
    }
    return $response;
}

$dir = sys_get_temp_dir() . '/swoole-pipeline-discard-' . getmypid();
mkdir($dir);
$discarded = new Swoole\Atomic();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $dir, $discarded) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    stream_set_timeout($client, 2);
    fwrite($client, "GET /discard HTTP/1.1\r\nHost: localhost\r\n\r\nGET /kept HTTP/1.1\r\nHost: localhost\r\n\r\n");
    $response = read_kept($client);
    Assert::same(substr_count($response, 'HTTP/1.1 200 OK'), 1);
    Assert::contains($response, 'kept');

    // Over package_max_length, so the reactor writes the file to upload_tmp_dir before dispatching.
    $body = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" .
        "Content-Type: text/plain\r\n\r\n" . str_repeat('A', 80 * 1024) . "\r\n--boundary--\r\n";
    fwrite($client, "POST /discard HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=boundary\r\n" .
        'Content-Length: ' . strlen($body) . "\r\n\r\n" . $body);
    $deadline = microtime(true) + 2;
    while (($discarded->get() < 2 || glob($dir . '/swoole.upfile.*')) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($discarded->get(), 2);
    Assert::same(glob($dir . '/swoole.upfile.*'), []);
    fwrite($client, "GET /kept HTTP/1.1\r\nHost: localhost\r\n\r\n");
    $response = read_kept($client);
    Assert::same(substr_count($response, 'HTTP/1.1 200 OK'), 1);
    Assert::contains($response, 'kept');
    fclose($client);
    $pm->kill();
    Assert::true(rmdir($dir));
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $dir, $discarded) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'package_max_length' => 65536,
        'upload_max_filesize' => 1024 * 1024,
        'upload_tmp_dir' => $dir,
        'dispatch_func' => function (Swoole\Server $server, int $fd, int $type, string $data) use ($discarded) {
            if (str_contains($data, ' /discard ')) {
                $discarded->add();
                return SWOOLE_DISPATCH_RESULT_DISCARD_PACKET;
            }
            return 0;
        },
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(substr($request->server['request_uri'], 1));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
