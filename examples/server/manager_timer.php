<?php
$serv = new Swoole\Server("0.0.0.0", 9501);

$serv->set(array(
    'worker_num' => 1,
));

$serv->on('managerStart', function ($erv) {
    echo "manager start\n";

    // sleep(30);

    $id = Swoole\Timer::tick(3000, function () {
        echo "timer 1\n";
    });

    Swoole\Timer::after(9000, function () use ($id) {
        echo "timer 2\n";
        Swoole\Timer::clear($id);

        Swoole\Timer::tick(2000, function () {
            echo "timer 3\n";
        });

        Swoole\Timer::tick(300, function () {
            echo "timer 4\n";
        });
    });
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd] receive data: $data\n";
    if ($serv->send($fd, "hello {$data}\n") == false)
    {
        echo "error\n";
    }

});

$serv->start();
