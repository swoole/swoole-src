<?php
$serv = new swoole_server("0.0.0.0", 9501);

$serv->set(array(
    'worker_num' => 1,
));

$serv->on('managerStart', function ($erv) {
    echo "manager start\n";

    // sleep(30);

    $id = swoole_timer_tick(3000, function () {
        echo "timer 1\n";
    });

    swoole_timer_after(9000, function () use ($id) {
        echo "timer 2\n";
        swoole_timer_clear($id);

        swoole_timer_tick(2000, function () {
            echo "timer 3\n";
        });

        swoole_timer_tick(300, function () {
            echo "timer 4\n";
        });
    });
});

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd] receive data: $data\n";
    if ($serv->send($fd, "hello {$data}\n") == false)
    {
        echo "error\n";
    }

});

$serv->start();
