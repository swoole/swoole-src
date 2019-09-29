--TEST--
swoole_server: bug_11000_01
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->childFunc = function () {
    $port = get_one_free_port();
    $serv = new Server(TCP_SERVER_HOST, $port);
    $process = new \Swoole\Process(function ($process) use ($serv) {
        usleep(10000);
        var_dump($serv->stats());
        $serv->shutdown();
    });
    $serv->set(['worker_num' => 2, 'log_file' => '/dev/null']);
    $serv->on('receive', function () { });
    $serv->addProcess($process);
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(11) {
  ["start_time"]=>
  int(%d)
  ["connection_num"]=>
  int(0)
  ["accept_count"]=>
  int(0)
  ["close_count"]=>
  int(0)
  ["worker_num"]=>
  int(2)
  ["idle_worker_num"]=>
  int(2)
  ["tasking_num"]=>
  int(0)
  ["request_count"]=>
  int(0)
  ["worker_request_count"]=>
  int(0)
  ["worker_dispatch_count"]=>
  int(0)
  ["coroutine_num"]=>
  int(0)
}
