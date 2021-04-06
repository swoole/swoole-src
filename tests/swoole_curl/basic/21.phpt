--TEST--
swoole_curl/basic: Test curl_getinfo() function with CURLINFO_CONTENT_TYPE parameter
--CREDITS--
Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $url  = "{$host}/get.php?test=contenttype";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    var_dump(curl_getinfo($ch, CURLINFO_CONTENT_TYPE));
    curl_close($ch);
});

?>
===DONE===
--EXPECTF--
string(24) "text/plain;charset=utf-8"
===DONE===
