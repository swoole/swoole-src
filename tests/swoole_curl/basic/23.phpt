--TEST--
swoole_curl/basic: Test curl_setopt() function with CURLOPT_HEADER parameter set to 1
--CREDITS--
Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "{$host}/get.php?test=header_body");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    $result = curl_exec($ch);

    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headerContent = substr($result, 0, $headerSize);
    $body = substr($result, $headerSize);

    Assert::assert(false !== strpos($headerContent, 'abc: 123'));

    var_dump($body);

    curl_close($ch);
});

?>
===DONE===
--EXPECTF--
string(5) "a
b
c"
===DONE===
