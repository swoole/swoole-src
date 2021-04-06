--TEST--
swoole_curl/basic: Test curl_error() & curl_errno() function with problematic protocol
--CREDITS--
TestFest 2009 - AFUP - Perrick Penet <perrick@noparking.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php if (!extension_loaded("curl")) print "skip"; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->disableNativeCurl();
$cm->run(function ($host) {
    $url = uniqid()."://www.".uniqid().".".uniqid();
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);

    curl_exec($ch);
    var_dump(curl_error($ch));
    var_dump(curl_errno($ch));
    curl_close($ch);

}, false);
?>
--EXPECTREGEX--
string\(\d+\) ".+URL.+"
int\(\d\)
