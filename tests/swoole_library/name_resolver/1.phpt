--TEST--
swoole_library/name_resolver: resolve
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Http\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\NameResolver\Consul;
use Swoole\NameResolver\Redis;

use function Swoole\Coroutine\run;

const SERVICE_NAME = 'test_service';
const REQ_N = 16;
const PORT_N = 3;

$config = TEST_NAME_RESOLVER;
$ns = new $config['class']($config['server_url']);
Coroutine::set(['name_resolver' => [$ns]]);

$html = base64_encode(random_bytes(rand(2048, 65536 * 2)));

$pm = new SwooleTest\ProcessManager;
$pm->initFreePorts(PORT_N);

$pm->parentFunc = function ($pid) use ($pm, $ns, $html) {
    Coroutine::set(['name_resolver' => [$ns]]);
    run(function () use ($html) {
        swoole_loop_n(REQ_N, function () use ($html) {
            $client = new Client(SERVICE_NAME);
            $client->set(['max_retries' => PORT_N]);
            $r = $client->get('/');
            Assert::true($r);
            Assert::eq($client->getBody(), $html);
        });
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $ns, $html) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(0), SERVER_MODE_RANDOM);
    $serv->addListener('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    $serv->set([
        'log_file' => '/dev/null',
    ]);
    $serv->on("workerStart", function ($serv, $workerId) use ($pm, $ns) {
        if ($workerId == 0) {
            swoole_loop_n(PORT_N, function ($i) use ($pm, $ns) {
                $ns->join(SERVICE_NAME, '127.0.0.1', $pm->getFreePort($i));
            });
            $pm->wakeup();
        }
    });
    $serv->on('request', function ($req, $resp) use ($pm, $html) {
        if ($req->server['server_port'] == $pm->getFreePort(1)) {
            $resp->status(503);
            $resp->end();
            return;
        }
        $resp->end($html);
    });
    $serv->on('beforeShutdown', function ($serv) use ($pm, $ns) {
        swoole_loop_n(PORT_N, function ($i) use ($pm, $ns) {
            $ns->leave(SERVICE_NAME, '127.0.0.1', $pm->getFreePort($i));
        });
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
DONE
