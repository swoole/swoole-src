--TEST--
swoole_server/object: getInstance
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_function_not_exist('posix_getpid');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $json = json_decode(httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/"));
        Assert::assert($json->result);
        $pm->kill();
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'log_level' => SWOOLE_LOG_ERROR,
    ));
    $serv->on("workerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Request', function ($req, $resp) use ($serv) {
        $fn = function () {
            $serv = Swoole\Server::getInstance();
            return $serv->getWorkerId();
        };
        $resp->end(json_encode(['result' => $fn() == $serv->getWorkerId()]));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
