--TEST--
swoole_server/object: getMasterPid
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
    $atomic = new \Swoole\Atomic(0);
    $serv = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'log_level' => SWOOLE_LOG_ERROR,
    ));
    $serv->on("start", function (Swoole\Server $serv) use ($pm, $atomic) {
        $pm->wakeup();
        $atomic->set(posix_getpid());
    });
    $serv->on('Request', function ($req, $resp) use ($serv, $atomic) {
        $resp->end(json_encode(['result' => $atomic->get() == $serv->getMasterPid()]));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
