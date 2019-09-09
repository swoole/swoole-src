--TEST--
swoole_library/curl/basic: Test curl_multi_getcontent() function
--CREDITS--
Sebastian Deutsch <sebastian.deutsch@9elements.com>
TestFest 2009 - AFUP - Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
/* Prototype  : bool curl_setopt(resource ch, int option, mixed value)
 * Description: Set an option for a cURL transfer
 * Source code: ext/curl/interface.c
 * Alias to functions:
 */
require __DIR__ . '/../../../include/bootstrap.php';
$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    // start testing
    echo '*** Testing curl method curl_multi_getcontent ***' . "\n";
    $url = "{$host}/get.php?test=curl_multi_getcontent";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
    curl_close($ch);
    Assert::assert(null === curl_multi_getcontent($ch));

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    $curl_content = curl_exec($ch);
    curl_close($ch);
    Assert::assert($curl_content === curl_multi_getcontent($ch));

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    $curl_content = curl_exec($ch);
    curl_close($ch);
    Assert::assert($curl_content === curl_multi_getcontent($ch));
});
?>
===DONE===
--EXPECTF--
*** Testing curl method curl_multi_getcontent ***
===DONE===