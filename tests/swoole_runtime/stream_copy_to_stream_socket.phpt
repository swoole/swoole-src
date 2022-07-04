--TEST--
swoole_runtime: stream_copy_to_stream() with socket as $source
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
$sockets = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
if (!$sockets) die("skip stream_socket_pair");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

Swoole\Runtime::enableCoroutine();

run(function () {
    $port = get_one_free_port();
    $uri = "tcp://127.0.0.1:{$port}";
    go(function () use ($uri) {
        $socket = stream_socket_server($uri, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$socket) {
            echo "$errstr ($errno)<br />\n";
        } else {
            $local = stream_socket_accept($socket);
            $remote = stream_socket_client("tcp://www.baidu.com:80", $errno, $errstr, 30, STREAM_CLIENT_CONNECT);
            go(function () use ($local, $remote) {
                stream_copy_to_stream($local, $remote);
            });
            stream_copy_to_stream($remote, $local);
            fclose($local);
            fclose($remote);
            fclose($socket);
        }
    });
    $fp = stream_socket_client($uri, $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $http = "GET / HTTP/1.0\r\nAccept: */*User-Agent: Lowell-Agent\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n";
        fwrite($fp, $http);
        $content = '';
        while (!feof($fp)) {
            $content .= fread($fp, 1024);
        }
        fclose($fp);
        Assert::assert(strpos($content,'map.baidu.com') !== false);
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
