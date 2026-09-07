--TEST--
swoole_server: bug Github#6196
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Coroutine;
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;
use SwooleTest\ProcessManager;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function() use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['socket_buffer_size' => 1024]);
        $client->upgrade('/');
        Coroutine::sleep(3);
        $client->close();
    });
    Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $results = [];
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->ports[0]->set(['socket_buffer_size' => 8 * 1024 * 1024 ]);
    $server->set([
        'worker_num' => 1,
        'send_yield' => true,
        'send_timeout' => 0,
        'log_level' => '/dev/null',
        'hook_flags' => SWOOLE_HOOK_ALL,
        'enable_coroutine' => true,
    ]);

    $server->on('message', function () {});
    $server->on('close', function ($server, $fd) {
        echo $fd . ' close' . PHP_EOL;
    });

    $server->on('open', function ($server, $request) use (&$results) {
        $wsFd = $request->fd;
        for ($i = 0; $i < 1000; $i++) {
            Coroutine::create(function () use ($server, $wsFd, $i, &$results) {
                $server->push($wsFd, str_repeat('x', 128 * 1024) . $i);
                $results[] = swoole_last_error();
            });
        }
    });

    $server->start();
    $counts = array_count_values($results);
    var_dump(isset($counts[SWOOLE_ERROR_CO_CANCELED]) && $counts[SWOOLE_ERROR_CO_CANCELED] > 0);
    var_dump(sizeof($results));
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%d close
bool(true)
int(1000)
