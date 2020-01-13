--TEST--
swoole_http_server: http chunk with send yield
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const ONE_MEGABYTES = 1024 * 1024;
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->initRandomData(1, 64 * ONE_MEGABYTES);
    $pm->parentFunc = function ($pid) use ($pm) {
        Swoole\Coroutine\run(function () use ($pm) {
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
            Assert::assert($data === $pm->getRandomData());
            phpt_var_dump(strlen($data));
        });
        $pm->kill();
        echo "DONE\n";
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $http->set([
            'log_file' => '/dev/null',
            'send_yield' => true,
            'http_compression' => false
        ]);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
            $data = $pm->getRandomData();
            $data_len = strlen($data);
            $offset = 0;
            do {
                $send_bytes = min($data_len - $offset, ONE_MEGABYTES);
                Assert::assert($response->write(substr($data, $offset, $send_bytes)) === true);
                $offset += $send_bytes;
            } while ($offset < $data_len);
            $response->end();
        });
        $http->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
DONE
DONE
