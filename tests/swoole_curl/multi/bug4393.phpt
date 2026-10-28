--TEST--
swoole_curl/multi: guzzle
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use GuzzleHttp\Client;
use GuzzleHttp\Promise;

use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->setParentSetup(function () { Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL); });
$pm->parentFunc = function () use ($pm) {
    try {
        run(function () use ($pm) {
            $guzzle = new Client(['base_uri' => 'http://127.0.0.1:' . $pm->getFreePort(), 'timeout' => 5]);
            for ($i = 0; $i < 2; $i++) {
                $promises = [
                    'first' => $guzzle->getAsync('/first'),
                    'second' => $guzzle->getAsync('/second'),
                ];
                foreach (Promise\Utils::settle($promises)->wait() as $name => $result) {
                    Assert::same($result['state'], 'fulfilled');
                    Assert::same((string) $result['value']->getBody(), '/' . $name);
                }
            }
            echo "Done\n";
        });
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $gate = null;
    $arrived = 0;
    $server->on('workerStart', function () use ($pm, &$gate) {
        $gate = new Swoole\Coroutine\Channel(1);
        $pm->wakeup();
    });
    $server->on('request', function ($request, $response) use (&$gate, &$arrived) {
        // Neither request can finish until both have arrived. This verifies asynchronous
        // execution without depending on public websites or a wall-clock speed threshold.
        if (++$arrived % 2 === 1) {
            Assert::true($gate->pop(5));
        } else {
            $gate->push(true);
        }
        $response->end($request->server['request_uri']);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
