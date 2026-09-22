--TEST--
swoole_server: send after the peer closed must fail instead of yielding (Github#6196)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Event;
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;
use SwooleTest\ProcessManager;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['socket_buffer_size' => 1024]);
        $client->upgrade('/');
        // never read the frames, so the output buffer of the server is filled up
        Coroutine::sleep(3);
        $client->close();
        // give the child the chance to report the result of the send after the close
        Coroutine::sleep(2);
    });
    Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->ports[0]->set(['socket_buffer_size' => 8 * 1024 * 1024]);
    $server->set([
        'worker_num' => 1,
        'send_yield' => true,
        // bounded, so that the old behavior fails instead of hanging forever
        'send_timeout' => 1,
        'log_file' => '/dev/null',
        'hook_flags' => SWOOLE_HOOK_ALL,
        'enable_coroutine' => true,
    ]);

    $server->on('message', function () {});

    $server->on('open', function ($server, $request) {
        for ($i = 0; $i < 1000; $i++) {
            Coroutine::create(function () use ($server, $request) {
                $server->push($request->fd, str_repeat('x', 128 * 1024));
            });
        }
    });

    $server->on('close', function ($server, $fd) {
        /**
         * The peer is gone while the output buffer is still overflowed, so this send must fail
         * immediately. conn->overflow is only reset by the write event, which will never come
         * again, so reporting it as SW_ERROR_OUTPUT_SEND_YIELD would suspend the coroutine on an
         * event that is never delivered.
         */
        $ret = $server->send($fd, 'test');
        echo 'send-after-close: ',
            ($ret === false && swoole_last_error() === SWOOLE_ERROR_SESSION_CLOSED_BY_CLIENT) ? 'OK' : 'FAIL',
            ' ret=',
            var_export($ret, true),
            ' err=',
            swoole_last_error(),
            PHP_EOL;
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
send-after-close: OK ret=false err=1002
