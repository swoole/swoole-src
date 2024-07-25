--TEST--
swoole_http_server: tmp content-type
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use GuzzleHttp\Client as GuzzleHttpClient;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

register_shutdown_function(function (){
   phpt_show_usage();
});

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $client = new GuzzleHttpClient();
        $baseUrl = 'http://127.0.0.1:' . $pm->getFreePort();
        $res = $client->post($baseUrl . '/', [
            'multipart' => [
                [
                    'name' => 'file',
                    'contents' => fopen(__FILE__, 'r'),
                    'filename' => basename(__FILE__),
                    'headers' => ['Content-Type' => 'application/php-script']
                ],
            ],
        ]);

        $status = $res->getStatusCode();
        $body = $res->getBody()->getContents();
        Assert::eq($status, 200);
        $result = json_decode($body, true);
        Assert::eq($result['file']['name'], basename(__FILE__));
        Assert::eq($result['file']['type'], 'application/php-script');
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $response->end(json_encode($request->files));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
