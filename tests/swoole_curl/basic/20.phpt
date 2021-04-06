--TEST--
swoole_curl/basic: Test curl_getinfo() function with CURLINFO_HTTP_CODE parameter
--CREDITS--
Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "{$host}/get.php?test=";
    $ch  = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    var_dump(curl_getinfo($ch, CURLINFO_HTTP_CODE));
    curl_close($ch);
});
?>
===DONE===
--EXPECTF--
Hello World!
Hello World!int(200)
===DONE===
