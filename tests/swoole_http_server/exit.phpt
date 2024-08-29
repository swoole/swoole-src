--TEST--
swoole_http_server: exit function
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80400) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.4 or higher');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
		try {
			exit('Swoole Server exit!!!');
		} catch (Exception $e) {
			echo $e->getMessage().PHP_EOL;
		}

		try {
			exit();
		} catch (Exception $e) {
			echo $e->getMessage().PHP_EOL;
		}

		try {
			exit(400);
		} catch (Exception $e) {
			echo $e->getStatus().PHP_EOL;
		}
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Swoole Server exit!!!
swoole exit
400
DONE
