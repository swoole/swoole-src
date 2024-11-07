--TEST--
swoole_lock: coroutine lock
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Lock;
use Swoole\Runtime;
use Swoole\Http\Server;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\WaitGroup;

if (defined('SWOOLE_IOURING_SQPOLL')) {
	swoole_async_set([
	    'iouring_workers' => 32,
	    'iouring_entries' => 20000,
	    'iouring_flag' => SWOOLE_IOURING_SQPOLL
	]);
}

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
	Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    run(function () use ($pm) {
        $waitGroup = new WaitGroup();
        go(function () use ($pm, $waitGroup) {
            $waitGroup->add();
            $resp = httpPost("http://127.0.0.1:{$pm->getFreePort()}?value=1", []);
            $respData = json_decode($resp, true);
            var_dump($respData);
            $waitGroup->done();
        });
        go(function () use ($pm, $waitGroup) {
            $waitGroup->add();
            $resp = httpPost("http://127.0.0.1:{$pm->getFreePort()}?value=2", []);
            $respData = json_decode($resp, true);
            var_dump($respData);
            $waitGroup->done();
        });
		go(function () use ($pm, $waitGroup) {
            $waitGroup->add();
            $resp = httpPost("http://127.0.0.1:{$pm->getFreePort()}?value=3", []);
            $respData = json_decode($resp, true);
            var_dump($respData);
            $waitGroup->done();
        });

		$waitGroup->wait();
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
	$lock = new Lock(SWOOLE_COROLOCK);
	var_dump($lock->lock());
	var_dump($lock->unlock());
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 4,
        'enable_coroutine' => true,
        'hook_flags' => SWOOLE_HOOK_ALL
    ]);

    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($lock) {
        $resp->header('Content-Type', 'text/plain');
        if ($req->get['value'] == 1 || $req->get['value'] == 2) {
            $lock->lock();
            if ($req->get['value'] == 1) {
                sleep(1);
            }
            $resp->end(json_encode(['result' => 'lock' . $req->get['value']]) . PHP_EOL);
            $lock->unlock();
        } else {
            $resp->end(json_encode(['result' => 'value 3']) . PHP_EOL);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%s
bool(false)
%s
bool(false)
array(1) {
  ["result"]=>
  string(7) "value 3"
}
array(1) {
  ["result"]=>
  string(5) "lock1"
}
array(1) {
  ["result"]=>
  string(5) "lock2"
}
DONE
