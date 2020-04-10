--TEST--
swoole_http_client_coro: compression with big data
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(1, [1, 4, 8, 32][PRESSURE_LEVEL] * 1024 * 1024);
$pm->parentFunc = function () use ($pm) {
    Co\Run(function () use ($pm) {
        $random = $pm->getRandomData();
        foreach ([[], ['download' => ['/', TEST_LOG_FILE]]] as $download) {
            foreach (['deflate', 'gzip', 'br'] as $compression) {
                $response = httpRequest(
                    "http://127.0.0.1:{$pm->getFreePort()}",
                    ['headers' => ['Accept-Encoding' => $compression]] + $download
                );
                Assert::same(
                    empty($download) ? $response['body'] : file_get_contents(TEST_LOG_FILE),
                    $random
                );
                if (empty($download)) {
                    phpt_var_dump($response['headers']['content-encoding'] ?? 'no-compression');
                    var_dump($response['headers']['content-encoding'] ?? $compression);
                }
            }
        }
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        static $random;
        if (!$random) {
            $random = $pm->getRandomData();
        }
        $response->end($random);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
string(7) "deflate"
string(4) "gzip"
string(2) "br"
