--TEST--
swoole_library/curl/basic: Test curl_error() & curl_errno() function without url
--CREDITS--
TestFest 2009 - AFUP - Perrick Penet <perrick@noparking.net>
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php if (!extension_loaded("curl")) print "skip"; ?>
--FILE--
<?php

//In January 2008 , level 7.18.0 of the curl lib, many of the messages changed.
//The final crlf was removed. This test is coded to work with or without the crlf.

require __DIR__ . '/../../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $ch = curl_init();

    curl_exec($ch);
    var_dump(curl_error($ch));
    var_dump(curl_errno($ch));
    curl_close($ch);

}, false);

?>
--EXPECTF--
%string(%d) "No URL set or URL using bad/illegal format"
int(3)
