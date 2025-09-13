--TEST--
swoole_http_client_coro: auto close
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        $client->push('hello world', SWOOLE_WEBSOCKET_OPCODE_TEXT);
        while ($client->recv()) {
        }
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_websocket_close_frame' => true
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });


    $server->on('message', function (Server $server, Frame $frame) use ($pm) {
        if ($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE) {
            Assert::true($frame->reason == 'Normal closure');
            $server->close($frame->fd);
            var_dump($frame);
            return;
        }

        $close = new CloseFrame();
        $close->code = 1000;
        $close->reason = 'Normal closure';
        $close->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
        $server->push($frame->fd, $close);
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
object(Swoole\WebSocket\CloseFrame)#%d (%d) {
  ["fd"]=>
  int(%d)
  ["data"]=>
  string(0) ""
  ["opcode"]=>
  int(8)
  ["flags"]=>
  int(33)
  ["finish"]=>
  bool(true)
  ["code"]=>
  int(1000)
  ["reason"]=>
  string(14) "Normal closure"
}