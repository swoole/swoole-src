--TEST--
swoole_runtime: stream context
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole\runtime::enableCoroutine();

go(function () {
    $opts = array(
        'socket' => array(
            'bindto' => '0:7000',
        ),
    );
    $ctx = stream_context_create($opts);
    $fp = stream_socket_client("tcp://www.baidu.com:80", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($fp, "GET / HTTP/1.0\r\nHost: www.baidu.com\r\nAccept: */*\r\n\r\n");
        $content = '';
        stream_set_timeout($fp, 5, 30000);
        while (!feof($fp)) {
            $content .= fread($fp, 8192);
        }
        fclose($fp);
        Assert::assert(strpos($content,'map.baidu.com') !== false);
    }
});
swoole_event_wait();
?>
--EXPECT--
