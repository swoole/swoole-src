--TEST--
swoole_library/curl/basic: Test curl_opt() function with POST parameters
--CREDITS--
Sebastian Deutsch <sebastian.deutsch@9elements.com>
TestFest 2009 - AFUP - Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    // start testing
    echo '*** Testing curl sending through GET an POST ***' . "\n";

    $url = "{$host}/get.php?test=getpost&get_param=Hello%20World";
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "Hello=World&Foo=Bar&Person=John%20Doe");
    curl_setopt($ch, CURLOPT_URL, $url); //set the url we want to use

    $curl_content = curl_exec($ch);
    curl_close($ch);

    var_dump( $curl_content );
});
?>
===DONE===
--EXPECTF--
*** Testing curl sending through GET an POST ***
string(208) "array(2) {
  ["test"]=>
  string(7) "getpost"
  ["get_param"]=>
  string(11) "Hello World"
}
array(3) {
  ["Hello"]=>
  string(5) "World"
  ["Foo"]=>
  string(3) "Bar"
  ["Person"]=>
  string(8) "John Doe"
}
"
===DONE===
