--TEST--
swoole_curl/basic: Test curl_opt() function with setting auto referer
--CREDITS--
Sebastian Deutsch <sebastian.deutsch@9elements.com>
TestFest 2009 - AFUP - Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
/* Prototype  : bool curl_setopt(resource ch, int option, mixed value)
 * Description: Set an option for a cURL transfer
 * Source code: ext/curl/interface.c
 * Alias to functions:
 */

require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->disableNativeCurl();
$cm->run(function ($host) {

    // start testing
    echo '*** Testing curl setting auto referer ***' . "\n";

    $url = "{$host}/get.php?test=auto_referer";
    $ch = curl_init();

    ob_start();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_AUTOREFERER, true);
    curl_setopt($ch, CURLOPT_URL, $url);

    $curl_content = curl_exec($ch);

    curl_close($ch);

    Assert::assert("http://{$host}/get.php?test=auto_referer" === $curl_content);
});

?>
===DONE===
--EXPECTF--
*** Testing curl setting auto referer ***
===DONE===
