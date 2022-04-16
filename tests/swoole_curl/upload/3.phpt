--TEST--
swoole_curl/upload: CURL file uploading[INFILE]
--INI--
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Runtime;
use SwooleTest\CurlManager;

require __DIR__ . '/../../include/bootstrap.php';

$cm = new CurlManager();
$cm->run(function ($host) {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "{$host}/get.php?test=input");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_PUT, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $fp = fopen(TEST_IMAGE, 'r');
    curl_setopt($ch, CURLOPT_INFILE, $fp);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Expect:"));
    curl_setopt($ch, CURLOPT_INFILESIZE, filesize(TEST_IMAGE));

    $http_result = curl_exec($ch);
    Assert::eq(md5($http_result), md5_file(TEST_IMAGE));
});

?>
--EXPECTF--
