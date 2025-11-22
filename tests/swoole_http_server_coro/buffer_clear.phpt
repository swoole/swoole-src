--TEST--
swoole_http_server_coro: websocket buffer clear
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
	go(function() use ($pm) {
		$client = new Client('127.0.0.1', $pm->getFreePort());
		$ret = $client->upgrade('/');
		$client->set(['open_websocket_pong_frame' => true]);
		$client->push('hello world');
		$client->push('ping', SWOOLE_WEBSOCKET_OPCODE_PING);
		$frame1 = $client->recv();
		$frame2 = $client->recv();
		Assert::eq($frame1->data, 'received: hello world');
		Assert::eq($frame1->opcode, SWOOLE_WEBSOCKET_OPCODE_TEXT);
		Assert::eq($frame2->data, 'ping');
		Assert::eq($frame2->opcode, SWOOLE_WEBSOCKET_OPCODE_PONG);
	});

	Event::wait();
	$pm->kill();
};

$pm->childFunc = function () use ($pm) {
	go(function () use ($pm) {
		$server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            $response->upgrade();
			while ($frame = $response->recv()) {
				$response->push('received: ' . $frame->data);
			}
        });
        $pm->wakeup();
        $server->start();
    });
    Event::wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
