--TEST--
swoole_iouring: iouring socket bug: https://github.com/walkor/workerman/issues/1161
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_iouring();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;

run(function() {
    // 目标地址
    $host = 'www.qq.com';
    $path = '/';

    $request = "GET {$path} HTTP/1.1\r\n";
    $request .= "Host: {$host}\r\n";
    $request .= "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0\r\n";
    $request .= "Connection: close\r\n";
    $request .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $request .= "\r\n";

    $fp = stream_socket_client("tcp://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT);
    if (!$fp) {
        return;
    }
    stream_set_blocking($fp, false);
    $result = stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    Assert::true($result);
    fwrite($fp, $request);
    $response = '';
    while (true) {
        $read = [$fp];
        $write = [];
        $except = [$fp];

        $num_changed = stream_select($read, $write, $except, 0);

        if ($num_changed === false) {
            break;
        }

        if ($num_changed > 0) {
            if (!empty($except)) {
                break;
            }

            if (!empty($read)) {
                $data = fread($fp, 4096);
                if ($data === false) {
                    break;
                }
                if ($data === '') {
                    break;
                }
                $response .= $data;
            }
        }
    }

    fclose($fp);
    Assert::contains($response, 'Tencent');
});
?>
--EXPECTF--
