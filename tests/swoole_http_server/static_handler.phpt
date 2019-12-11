--TEST--
swoole_http_server: static file handler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test.jpg");
        Assert::assert(!empty($data));

        $data2 = file_get_contents(TEST_IMAGE);
        for($i=0;$i<strlen($data); $i++) {
            if (!isset($data2[$i])) {
                echo "no index $i\n";
                var_dump(substr($data, $i));
                break;
            }
            if ($data[$i] != $data2[$i]) {
                var_dump($i);
                break;
            }
        }
        Assert::assert(md5($data) === md5_file(TEST_IMAGE));
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/',
        'static_file_types' => [],
        'static_file_locations' => ["/static", "/"]
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (Request $request, Response $response) {
        $response->end("hello world");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
