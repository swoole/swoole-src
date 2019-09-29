--TEST--
swoole_server: user process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;
use Swoole\Client;
$pm = new SwooleTest\ProcessManager;

const SIZE = 8192* 5;

$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set(["open_eof_check" => true, "package_eof" => "\r\n\r\n"]);
    $r = $client->connect('127.0.0.1', $pm->getFreePort(), -1);
    if ($r === false)
    {
        echo "ERROR";
        exit;
    }
    $client->send("SUCCESS");
    for($i=0; $i < 20; $i++) {
      $ret = $client->recv();
      Assert::same(strlen($ret), SIZE +4);
    }
    $client->close();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);

    $proc = new swoole\process(function ($process) use ($serv){
      //echo posix_getpid()."\n";
      while(true) {
       $data = json_decode($process->read(), true);
       //var_dump(SIZE);
       for($i=0; $i < 10; $i++) {
         $serv->send($data['fd'], str_repeat('A', SIZE)."\r\n\r\n");
         //echo "user process send ok\n";
       }
     }
    }, false, true);

    $serv->addProcess($proc);
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data) use ($proc)
    {
        $proc->write(json_encode(['fd' => $fd]));
        for($i=0; $i < 10; $i++) {
          $serv->send($fd, str_repeat('A', SIZE)."\r\n\r\n");
          //echo "worker send ok\n";
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
