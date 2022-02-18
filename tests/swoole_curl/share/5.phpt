--TEST--
swoole_curl/share: Basic curl_share test
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();

$cm->run(function ($host) {
    $sh = curl_share_init();
    curl_share_setopt($sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);

    $cookie_value = 'swoole';
    $cookie_name = 'test_cookie';

    $url = "{$host}/get.php?test=cookie_set&cookie_name={$cookie_name}&cookie_value={$cookie_value}&cookie_expire=" . (time() + 3600);

    $ch1 = curl_init($url);
    curl_setopt($ch1, CURLOPT_SHARE, $sh);
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch1, CURLOPT_COOKIEFILE, "");
    $rs1 = curl_exec($ch1);
    Assert::notEmpty($rs1);
    Assert::eq(json_decode($rs1), true);

    $url = "{$host}/get.php?test=cookie_get";
    $ch2 = curl_init($url);
    curl_setopt($ch2, CURLOPT_SHARE, $sh);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch2, CURLOPT_COOKIEFILE, "");
    $rs2 = curl_exec($ch2);
    Assert::notEmpty($rs2);
    Assert::eq(json_decode($rs2)->$cookie_name, $cookie_value);
    curl_share_close($sh);

    curl_close($ch1);
    curl_close($ch2);
});


?>
--EXPECT--
