--TEST--
swoole_http_server: buffer output size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('RANDOM_CHAR', get_safe_random(1));
define('OUTPUT_BUFFER_SIZE', pow(2, 12));
define('HTTP_HEADER_SIZE', pow(2, 8));
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $response = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}", ['timeout' => 0.1]);
        Assert::same(strrpos($response, RANDOM_CHAR) + 1, OUTPUT_BUFFER_SIZE - HTTP_HEADER_SIZE);
        Assert::throws(function () use ($pm) {
            $response = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/full", ['timeout' => 0.1]);
        }, Exception::class);
        echo file_get_contents(TEST_LOG_FILE);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    @unlink(TEST_LOG_FILE);
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => TEST_LOG_FILE,
        'http_compression' => false,
        'output_buffer_size' => OUTPUT_BUFFER_SIZE,
    ]);
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($server) {
        $length = $request->server['request_uri'] === '/full' ? OUTPUT_BUFFER_SIZE + 4096 : OUTPUT_BUFFER_SIZE - HTTP_HEADER_SIZE;
        $response->end(str_repeat(RANDOM_CHAR, $length));
    });
    $server->start();
    @unlink(TEST_LOG_FILE);
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	WARNING	ProcessFactory::finish() (ERRNO %d): The length of data [%d] exceeds the output buffer size[%d], please use the sendfile, chunked transfer mode or adjust the output_buffer_size
DONE
