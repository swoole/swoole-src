--TEST--
swoole_http_server/static_handler: link to a file outside the document root
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$doc_root = __DIR__ . '/docroot';
$image_dir = 'image/';
mkdir($doc_root);
mkdir($doc_root . '/' . $image_dir);
$image_link = $doc_root . '/' . $image_dir . '/image.jpg';
symlink(TEST_IMAGE, $image_link);

$cleanup_fn = function () use ($doc_root, $image_dir, $image_link) {
    if (is_file($image_link)) {
        unlink($image_link);
    }
    rmdir($doc_root . '/' . $image_dir);
    rmdir($doc_root);
};

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $doc_root, $image_dir, $image_link) {
    Swoole\Coroutine\run(function () use ($pm, $doc_root, $image_dir, $image_link) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/{$image_dir}/image.jpg");
        Assert::assert(md5($data) === md5_file(TEST_IMAGE));
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $doc_root, $image_dir, $image_link) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => $doc_root,
        'static_handler_locations' => ['/image']
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
