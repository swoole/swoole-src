--TEST--
swoole_library/curl/basic: Test curl_opt() function with CURLOPT_HTTP_VERSION/CURL_HTTP_VERSION_1_0
--CREDITS--
TestFest 2009 - AFUP - Xavier Gorse <xgorse@elao.com>
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
    echo '*** Testing curl with HTTP/1.0 ***' . "\n";

    $url = "{$host}/get.php?test=httpversion";
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_setopt($ch, CURLOPT_URL, $url); //set the url we want to use

    $curl_content = curl_exec($ch);
    curl_close($ch);

    var_dump( $curl_content );

});

?>
===DONE===
--EXPECTF--
*** Testing curl with HTTP/1.0 ***

Warning: swoole_curl: http version[1] not supported in %s on line %d
string(8) "HTTP/1.1"
===DONE===
