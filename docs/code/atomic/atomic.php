<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

$atomic = new Swoole\Atomic();

$serv = new Swoole\Server('127.0.0.1', 9501);
$serv->set([
               'worker_num' => 1
           ]);
$serv->on("start", function ($serv) use ($atomic) {
    var_dump('start:'. $atomic->get());
    if ($atomic->add() == 2) {
        var_dump('start:'. $atomic->get());
        $serv->shutdown();
    }
});
$serv->on("ManagerStart", function ($serv) use ($atomic) {
    var_dump('ManagerStart:'. $atomic->get());
    if ($atomic->add() == 2) {
        var_dump('ManagerStart:'. $atomic->get());
        $serv->shutdown();
    }
});
$serv->on("ManagerStop", function ($serv) {
    echo "shutdown\n";
});
$serv->on("Receive", function () {

});
$serv->start();
