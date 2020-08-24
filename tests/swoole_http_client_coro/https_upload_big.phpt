--TEST--
swoole_http_client_coro: upload a big file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

define('SSL_DIR', realpath(__DIR__.'/../../examples/ssl'));

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort(), true);
        $content = str_repeat(get_safe_random(1024), 5 * 1024);
        file_put_contents('/tmp/test.jpg', $content);
        $cli->addFile('/tmp/test.jpg', 'test.jpg');
        $cli->setHeaders([
            'md5' => md5($content),
        ]);
        $ret = $cli->post('/', ['name' => 'rango']);
        Assert::assert($ret);
        Assert::same($cli->statusCode, 200);
        Assert::eq($cli->body, 'success');
        $cli->close();
        @unlink('/tmp/test.jpg');
        echo "DONE\n";
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);

    $http->set([
        'log_file' => '/dev/null',
        'package_max_length' => 10 * 1024 * 1024,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);

    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::eq(md5_file($request->files['test_jpg']['tmp_name']) ,$request->header['md5']);
        $response->end('success');
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
