--TEST--
swoole_http2_server: sendfile delete_file removes the file after the synchronous send
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\System;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

$content = get_safe_random(256 * 1024);

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $path = tempnam('/tmp', 'swoole_http2_sendfile_delete_');
    file_put_contents($path, $content);

    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $path, $content) {
        Coroutine\run(function () use ($pm, $path, $content) {
            $client = new Client('127.0.0.1', $pm->getFreePort(), false);
            $client->set(['timeout' => 10]);
            Assert::true($client->connect());

            $request       = new Http2Request();
            $request->path = '/download';
            Assert::greaterThan($client->send($request), 0);
            $response = $client->recv();
            Assert::same($response->statusCode, 200);
            Assert::same(md5($response->data), md5($content));

            // The HTTP/2 source is consumed synchronously before the response returns, so
            // the file is deleted; poll within a deadline to absorb scheduling.
            for ($i = 0; $i < 200; $i++) {
                clearstatcache(true, $path);
                if (!is_file($path)) {
                    break;
                }
                System::sleep(0.025);
            }
            clearstatcache(true, $path);
            Assert::false(is_file($path));

            $client->close();
        });
        $pm->kill();
        @unlink($path);
    };
    $pm->childFunc = function () use ($pm, $mode, $path) {
        $http = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $http->set([
            'worker_num'          => 1,
            'log_file'            => '/dev/null',
            'open_http2_protocol' => true,
        ]);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Request $request, Response $response) use ($path) {
            $response->sendfile($path, 0, 0, true);
        });
        $http->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
