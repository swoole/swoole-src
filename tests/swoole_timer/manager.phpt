--TEST--
swoole_timer: timer in manager
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
const RES_FILE = __DIR__.'/result.txt';
file_put_contents(RES_FILE, "");

//设置等待10秒
$pm->setWaitTimeout(10);

$pm->parentFunc = function ($pid) use ($pm)
{
    $fp = fopen(RES_FILE, "rw");
    while(!feof($fp)) {
        $line = fgets($fp);
        if ($line) {
            echo $line;
        }
    }
    unlink(RES_FILE);
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server("0.0.0.0", $pm->getFreePort());

    $serv->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ));

    $serv->on('managerStart', function ($serv) use ($pm) {

        file_put_contents(RES_FILE, "start\n", FILE_APPEND);

        $id = swoole_timer_tick(300, function () {
            file_put_contents(RES_FILE, "timer 1\n", FILE_APPEND);
        });

        swoole_timer_after(900, function () use ($id, $serv, $pm) {
            file_put_contents(RES_FILE, "timer 2\n", FILE_APPEND);
            swoole_timer_clear($id);

            swoole_timer_tick(200, function ($id) use ($serv, $pm) {
                static $i = 0;
                file_put_contents(RES_FILE, "timer 3\n", FILE_APPEND);
                $i ++;
                if ($i > 4) {
                    file_put_contents(RES_FILE, "end\n", FILE_APPEND);
                    swoole_timer_clear($id);
                    $pm->wakeup();
                    $serv->shutdown();
                }
            });
        });
    });

    $serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {

    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
start
timer 1
timer 1
timer 1
timer 2
timer 3
timer 3
timer 3
timer 3
timer 3
end
