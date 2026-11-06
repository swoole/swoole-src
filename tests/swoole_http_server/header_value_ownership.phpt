--TEST--
swoole_http_server: preserve response header value ownership
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client as HttpClient;
use Swoole\Coroutine\Http2\Client as Http2Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $http1 = new HttpClient('127.0.0.1', $pm->getFreePort());
        $http1->setHeaders(['Accept-Encoding' => 'gzip']);
        Assert::true($http1->get('/http1'));
        $headers = $http1->getHeaders();
        Assert::same($headers['content-type'], 'text/html');
        Assert::false(isset($headers['content-encoding']));
        $http1->close();

        $state = new HttpClient('127.0.0.1', $pm->getFreePort());
        Assert::true($state->get('/http1-state'));
        Assert::same($state->getBody(), '746578742f68746d6c0920');
        $state->close();

        $http2 = new Http2Client('127.0.0.1', $pm->getFreePort());
        Assert::true($http2->connect());
        $request = new Http2Request;
        $request->path = '/http2';
        $request->headers = ['Accept-Encoding' => 'gzip'];
        $http2->send($request);
        $response = $http2->recv();
        Assert::same($response->headers['content-type'], 'text/html');
        Assert::false(isset($response->headers['content-encoding']));
        $http2->close();

        $state = new HttpClient('127.0.0.1', $pm->getFreePort());
        Assert::true($state->get('/http2-state'));
        Assert::same($state->getBody(), '746578742f68746d6c0920');
        $state->close();
    });

    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http_compression_types' => ['text/html'],
    ]);
    $values = [];
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use (&$values) {
        $path = $request->server['request_uri'];
        if (str_ends_with($path, '-state')) {
            $response->end($values[$path] ?? '');
            return;
        }

        $value = implode('', ['text/html', "\t "]);
        $response->header('Content-Type', $value);
        $response->end(str_repeat('A', 8192));
        $values[$path . '-state'] = bin2hex($value);
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
