--TEST--
swoole_http_server: url rewrite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$file1 = __DIR__ .'/static/3.html';
$file2 = __DIR__ .'/static/article/settings.html';

if (is_dir(__DIR__.'/static') === false) {
    mkdir(__DIR__.'/static');
}

if (is_dir(__DIR__.'/static/article') === false) {
    mkdir(__DIR__.'/static/article');
}

file_put_contents($file1, 'user_john_action_settings');
file_put_contents($file2, 'post_99_query_foo=bar');

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $file1, $file2) {
    foreach ([false, true] as $http2) {
        Swoole\Coroutine\run(function () use ($pm, $http2, $file1, $file2) {
            $options = ['http2' => $http2];

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/view/post/3", $options);
            Assert::same($response['statusCode'], 200);
            Assert::same($response['body'], 'user_john_action_settings');

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/view/post/99", $options);
            Assert::same($response['statusCode'], 404);

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/article/settings.html", $options);
            Assert::same($response['statusCode'], 200);
            Assert::same($response['body'], 'post_99_query_foo=bar');

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/article/not_exists.html", $options);
            Assert::same($response['statusCode'], 404);
        });
    }
    echo "DONE\n";
    $pm->kill();
    unlink($file1);
    unlink($file2);
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'log_file' => '/dev/null',
        'document_root' => __DIR__,
        'enable_static_handler' => true,
        'open_http2_protocol' => true,
        'static_handler_locations' => ['/static'],
        'url_rewrite_rules' => [
            '~^/view/post/(\d+)$~' => '/static/$1.html',
            '/article/' => '/static/article/'
        ]
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $response->end('dynamic_response');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
