--TEST--
swoole_curl/basic: Test curl_opt() function with user agent
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
$cm->run(function ($host) {
    // start testing
    echo '*** Testing curl with user agent ***' . "\n";

    $url = "{$host}/get.php?test=useragent";
    $ch = curl_init();

    ob_start(); // start output buffering
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'cURL phpt');
    curl_setopt($ch, CURLOPT_URL, $url); //set the url we want to use

    $curl_content = curl_exec($ch);
    curl_close($ch);

    var_dump( $curl_content );

});


?>
===DONE===
--EXPECTF--
*** Testing curl with user agent ***
string(9) "cURL phpt"
===DONE===
