--TEST--
swoole_curl/basic: Test curl_getinfo() function with CURLINFO_EFFECTIVE_URL parameter
--CREDITS--
Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $url = "http://{$host}/get.php?test=";
    $ch  = curl_init();

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    $info = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    var_dump($url == $info);
    curl_close($ch);
});
?>
===DONE===
--EXPECTF--
Hello World!
Hello World!bool(true)
===DONE===
