--TEST--
swoole_http2_server: sendfile streams a small range without buffering the whole file
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('getrusage');
if (PHP_OS !== 'Linux' && PHP_OS !== 'Darwin') {
    skip('unknown ru_maxrss unit convention');
}
if (!isset(getrusage()['ru_maxrss'])) {
    skip('ru_maxrss is not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

// A 128 MiB sparse file: the baseline reads it whole before selecting the range,
// the bounded implementation only touches a couple of 64 KiB windows.
$sparse_file = tempnam(sys_get_temp_dir(), 'swoole_sendfile_rss_');
register_shutdown_function(function () use ($sparse_file) {
    if (is_file($sparse_file)) {
        unlink($sparse_file);
    }
});
$handle = fopen($sparse_file, 'w');
ftruncate($handle, 128 * 1024 * 1024);
fclose($handle);

$offset = 64 * 1024 * 1024;
$range = 128 * 1024;
// Well above allocator noise for a couple of windows, well below the 128 MiB file.
$ceiling = 32 * 1024 * 1024;

$rss_delta = new Atomic\Long(0);
$measured = new Atomic(0);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $range, $ceiling, $rss_delta, $measured) {
    Coroutine\run(function () use ($pm, $range, $ceiling, $rss_delta, $measured) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        $client->set(['timeout' => 10]);
        Assert::true($client->connect());

        // Warm the worker so its baseline allocations are already counted.
        $request = new Http2Request;
        $request->path = '/warmup';
        Assert::greaterThan($client->send($request), 0);
        Assert::same($client->recv()->data, 'OK');

        // Request only a small range from deep inside the file.
        $request = new Http2Request;
        $request->path = '/measure';
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::notEmpty($response);
        Assert::same(strlen($response->data), $range);
        Assert::same($response->data, str_repeat("\0", $range));

        // The worker records its peak-RSS growth after sendfile() returns.
        $deadline = microtime(true) + 5;
        while ($measured->get() === 0 && microtime(true) < $deadline) {
            Coroutine::sleep(0.01);
        }
        Assert::same($measured->get(), 1);
        Assert::lessThan($rss_delta->get(), $ceiling);
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $sparse_file, $offset, $range, $rss_delta, $measured) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) use (
        $sparse_file,
        $offset,
        $range,
        $rss_delta,
        $measured
    ) {
        if ($request->server['request_uri'] !== '/measure') {
            $response->end('OK');
            return;
        }
        $before = getrusage()['ru_maxrss'];
        $response->sendfile($sparse_file, $offset, $range);
        $after = getrusage()['ru_maxrss'];
        // Linux reports ru_maxrss in KiB, macOS in bytes.
        $delta = $after - $before;
        $rss_delta->set(PHP_OS === 'Darwin' ? $delta : $delta * 1024);
        $measured->set(1);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
