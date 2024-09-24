--TEST--
swoole_http_server/static_handler: doc root with same prefix
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$doc1_root = __DIR__ . '/docroot';
$doc2_root = __DIR__ . '/docroot2';
mkdir($doc1_root);
mkdir($doc2_root);
file_put_contents($doc1_root . '/image.jpg', file_get_contents(TEST_IMAGE));
file_put_contents($doc2_root . '/uuid.txt', uniqid());

$cleanup_fn = function () use ($doc1_root, $doc2_root) {
    unlink($doc1_root . '/image.jpg');
    unlink($doc2_root . '/uuid.txt');
    rmdir($doc1_root);
    rmdir($doc2_root);
};

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $doc1_root, $doc2_root) {
    Swoole\Coroutine\run(function () use ($pm, $doc1_root, $doc2_root) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/../docroot/image.jpg");
        Assert::assert(md5($data) === md5_file(TEST_IMAGE));

        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/../docroot2/uuid.txt");
        Assert::isEmpty($data);
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $doc1_root, $doc2_root) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => $doc1_root,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
$cleanup_fn();
?>
--EXPECT--
DONE
