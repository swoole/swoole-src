--TEST--
swoole_http_client_coro: client continue frames - 4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;
use SwooleTest\ProcessManager as ProcessManager;

$data1 = bin2hex(random_bytes(10 * 1024));
$data2 = bin2hex(random_bytes(20 * 2048));
$data3 = bin2hex(random_bytes(40 * 4096));

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $results = [];
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $client->push('111', SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_FIN);
        $results[] = $client->recv();
        Assert::true($results[0]->data == $data1 . $data2 . $data3);
        $client->push('222', SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_FIN);
        $results[] = $client->recv();
        Assert::true($results[1]->data == $data3 . $data2 . $data1);
        Assert::true($results[0]->data != $results[1]->data);
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) use ($data1, $data2, $data3) {
            $response->upgrade();
            while ($frame = $response->recv()) {
                if ($frame->data == '111') {
                    $response->push($data1, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
                    $response->push($data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push($data3, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
                } else {
                    $response->push($data3, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
                    $response->push($data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push($data1, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
                }
            }
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
