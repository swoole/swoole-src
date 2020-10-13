--TEST--
swoole_http_server: response create
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(
        function () use ($pm) {
            $body = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}", ['timeout' => 0.1]);
            Assert::eq($body, 'hello world');
            $pm->kill();
        }
    );
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server("127.0.0.1", $pm->getFreePort());
    $serv->set([Constant::OPTION_LOG_FILE => '/dev/null']);
    $serv->on(
        Constant::EVENT_WORKER_START,
        function () use ($pm) {
            $pm->wakeup();
        }
    );
    $serv->on(
        'Receive',
        function ($serv, $fd, $tid, $data) {
            $resp = Swoole\Http\Response::create($serv, $fd);
            $resp->end("hello world");
        }
    );
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
