--TEST--
swoole_http2_client_coro: cookie limit
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
        'open_http2_protocol' => true,
    ]);
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $http->start();
    exit(0);
}

usleep(200000);

Swoole\Coroutine\run(function () use ($port) {
    $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $port);
    $cli->connect();

    $request = new Swoole\Http2\Request;
    $request->path = '/';
    $request->cookies = [
        'token' => str_repeat('b', 4097),
    ];
    try {
        $cli->send($request);
        echo "COOKIE_NOT_THROWN\n";
    } catch (Swoole\Coroutine\Http2\Client\Exception $e) {
        echo "COOKIE_THROWN\n";
    }
});

posix_kill($pid, SIGTERM);
pcntl_waitpid($pid, $status);
?>
--EXPECT--
COOKIE_THROWN
