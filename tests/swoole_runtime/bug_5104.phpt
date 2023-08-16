--TEST--
swoole_runtime: Github#5104 https://github.com/swoole/swoole-src/issues/5104
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
use function Co\run;

run(function () {
    $socket1 = stream_socket_server("tcp://0.0.0.0:8000");
    $socket2 = stream_socket_client("tcp://example.com:80");

    stream_set_blocking($socket1, 0);
    stream_set_blocking($socket2, 0);

    $read = [$socket1, $socket2];
    $write = [$socket2];
    $except = null;
    $timeout = null;
    stream_select($read, $write, $except, $timeout, null);

    if (in_array($socket1, $read)) {
      $client = stream_socket_accept($socket1);
      fwrite($client, "Hello world!\n");
      fclose($client);
    }
    if (in_array($socket2, $read)) {
      $response = fread($socket2, 1024);
    }
    if (in_array($socket2, $write)) {
      fwrite($socket2, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }
    echo 'DONE';
});
?>
--EXPECT--
DONE
