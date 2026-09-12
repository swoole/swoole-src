--TEST--
swoole_http_server: client reset when sending file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;
use Swoole\Coroutine\System;
use Swoole\Coroutine\Client;
use Swoole\Runtime;

$tmpFile = tempnam(sys_get_temp_dir(), 'swoole-sendfile-reset-');
$sendFile = get_safe_random(mt_rand(4, 8) * 1024 * 1024);
file_put_contents($tmpFile, $sendFile);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $tmpFile) {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    Co\run(function () use ($pm, $tmpFile) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set(['socket_buffer_size' => 128 * 1024]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $client->send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        $resp = '';

        Co\go(function () use ($pm, $tmpFile) {
            $file = file_get_contents('http://127.0.0.1:' . $pm->getFreePort());
            Assert::eq(md5_file($tmpFile), md5($file));
        });

        while (true) {
            $data = $client->recv(5.0);
            System::sleep(0.01);
            Assert::notEmpty($data);
            $resp .= $data;
            if (strlen($resp) > 2 * 1024 * 1024) {
                $client->close();
                break;
            }
        }
    });

    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $tmpFile) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($tmpFile) {
        $response->header('Content-Type', 'application/octet-stream');
        $response->header('Content-Disposition', 'attachment; filename=recvfile.txt');
        $response->sendfile($tmpFile);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
unlink($tmpFile);
?>
--EXPECT--
DONE
