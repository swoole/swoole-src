--TEST--
swoole_http_client_coro: header and cookie limits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!function_exists('pcntl_fork')) {
    die('skip pcntl required');
}
?>
--FILE--
<?php
function free_port(): int
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($server === false) {
        throw new RuntimeException("failed to find free port: $errstr");
    }
    $name = stream_socket_get_name($server, false);
    fclose($server);
    return (int) substr(strrchr($name, ':'), 1);
}

$port = free_port();
$pid = pcntl_fork();
if ($pid === -1) {
    throw new RuntimeException('pcntl_fork() failed');
}
if ($pid === 0) {
    $http = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $http->start();
    exit(0);
}

usleep(200000);

Swoole\Coroutine\run(function () use ($port) {
    $header_client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    $header_client->set(['timeout' => 3]);
    $header_client->setHeaders([
        'X-Big-Header' => str_repeat('a', 64 * 1024),
    ]);
    try {
        $header_client->get('/');
        echo "HEADER_NOT_THROWN\n";
    } catch (Swoole\Coroutine\Http\Client\Exception $e) {
        echo "HEADER_THROWN\n";
    }

    $cookie_client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    $cookie_client->set(['timeout' => 3]);
    $cookie_client->setCookies([
        'token' => str_repeat('b', 4097),
    ]);
    try {
        $cookie_client->get('/');
        echo "COOKIE_NOT_THROWN\n";
    } catch (Swoole\Coroutine\Http\Client\Exception $e) {
        echo "COOKIE_THROWN\n";
    }
});

posix_kill($pid, SIGTERM);
pcntl_waitpid($pid, $status);
?>
--EXPECT--
HEADER_THROWN
COOKIE_THROWN
