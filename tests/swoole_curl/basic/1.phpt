--TEST--
swoole_library/curl/basic: Test curl_exec() function with basic functionality
--CREDITS--
Sebastian Deutsch
<sebastian.deutsch@9elements.com>
TestFest 2009 - AFUP - Jean-Marc Fontaine
<jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();

$cm->run(function ($host) {
    // start testing
    echo "*** Testing curl_exec() : basic functionality ***\n";

    $url = $host. "/get.php?test=get";
    $ch = curl_init();

    ob_start(); // start output buffering
    curl_setopt($ch, CURLOPT_URL, $url); //set the url we want to use
    $ok = curl_exec($ch);
    curl_close($ch);
    $curl_content = ob_get_contents();
    ob_end_clean();

    if ($ok) {
        var_dump($curl_content);
    } else {
        echo "curl_exec returned false";
    }
});

?>
--EXPECTF--
*** Testing curl_exec() : basic functionality ***
string(25) "Hello World!
Hello World!"
