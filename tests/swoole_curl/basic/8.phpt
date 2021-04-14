--TEST--
swoole_curl/basic: Test curl_error() & curl_errno() function with problematic host
--CREDITS--
TestFest 2009 - AFUP - Perrick Penet <perrick@noparking.net>
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('curl');
$addr = "www." . uniqid() . "." . uniqid();
if (gethostbyname($addr) != $addr) {
    exit('skip catch all dns');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "http://www." . uniqid() . "." . uniqid();
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    var_dump(curl_error($ch));
    var_dump(curl_errno($ch));
    curl_close($ch);
}, false);
?>
--EXPECTF--
%s resolve%s
int(6)
