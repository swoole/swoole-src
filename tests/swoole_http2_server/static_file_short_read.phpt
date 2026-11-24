--TEST--
swoole_http2_server: abort short static-file ranges instead of sending unread bytes
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
$file = '/sys/devices/system/cpu/online';
skip('requires a readable sysfs file with a larger advertised size', !is_readable($file));
$length = strlen(file_get_contents($file));
skip('requires a short-read sysfs file', filesize($file) < 2100 || $length < 2 || $length >= 2000);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$directory = sys_get_temp_dir() . '/swoole-h2-short-read-' . getmypid();
mkdir($directory);
$file = $directory . '/online.txt';
symlink('/sys/devices/system/cpu/online', $file);
register_shutdown_function(static function () use ($file, $directory) {
    @unlink($file);
    @rmdir($directory);
});

$pm = new ProcessManager;
$pm->parentFunc = static function () use ($pm) {
    Swoole\Coroutine\run(static function () use ($pm) {
        $fetch = static function (string $range) use ($pm) {
            $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
            $client->set(['timeout' => 3]);
            Assert::true($client->connect());
            $request = new Swoole\Http2\Request;
            $request->path = '/online.txt';
            $request->headers = ['range' => $range];
            Assert::greaterThan($client->send($request), 0);
            $response = $client->recv();
            $client->close();
            return $response;
        };
        $response = $fetch('bytes=0-0');
        Assert::same($response->statusCode, 206);
        Assert::same(strlen($response->data), 1);
        $response = $fetch('bytes=0-0,1-1');
        Assert::same($response->statusCode, 206);
        Assert::same($response->headers['content-length'], (string) strlen($response->data));
        $content = file_get_contents('/sys/devices/system/cpu/online');
        foreach ([$content[0], $content[1]] as $byte) {
            Assert::contains($response->data, "\r\n\r\n" . $byte . "\r\n--");
        }

        // sysfs advertises a page, but returns only the short CPU-list text.
        // Cover a partial read, immediate EOF, and the single-range path.
        foreach (['bytes=0-2099,0-0', 'bytes=2000-2099,0-0', 'bytes=0-2099'] as $range) {
            Assert::false($fetch($range));
        }
        $response = $fetch('bytes=0-0');
        Assert::same(strlen($response->data), 1);
    });
    $pm->kill();
};
$pm->childFunc = static function () use ($pm, $directory) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'static_handler_locations' => ['/online.txt'],
        'open_http2_protocol' => true,
        'document_root' => $directory,
    ]);
    $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
    $server->on('Request', static function ($request, $response) { $response->end('unexpected fallback'); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
