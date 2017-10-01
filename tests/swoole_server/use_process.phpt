--TEST--
swoole_server: user process

--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;

const SIZE = 8192* 5;

$pm->parentFunc = function ($pid)
{
    $client = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set(["open_eof_check" => true, "package_eof" => "\r\n\r\n"]);
    $r = $client->connect("127.0.0.1", 9503, -1);
    if ($r === false)
    {
        echo "ERROR";
        exit;
    }
    $client->send("SUCCESS");
    for($i=0; $i < 20; $i++) {
      $ret = $client->recv();
      assert(strlen($ret) == SIZE +4);
    }
    $client->close();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server("127.0.0.1", 9503);
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
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data) use ($proc)
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
