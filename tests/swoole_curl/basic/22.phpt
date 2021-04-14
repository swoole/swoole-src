--TEST--
swoole_curl/basic: Test curl_setopt() function with CURLOPT_FOLLOWLOCATION parameter
--CREDITS--
Jean-Marc Fontaine <jmf@durcommefaire.net>
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    // CURLOPT_FOLLOWLOCATION = true
    $urls = [
        "{$host}/get.php?test=redirect_301",
        "{$host}/get.php?test=redirect_302",
        "{$host}/get.php?test=redirect_307",
        "{$host}/get.php?test=redirect_308",
    ];
    foreach($urls as $url) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'id=123&name=swoole');
        curl_exec($ch);
        $info = curl_getinfo($ch);

        Assert::assert(1 === $info['redirect_count']);
        
        curl_close($ch);
    }

    // CURLOPT_FOLLOWLOCATION = false
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_exec($ch);
    $info = curl_getinfo($ch);

    Assert::assert(0 === $info['redirect_count']);
    Assert::assert("http://{$host}/get.php?test=getpost" === $info['redirect_url']);

    curl_close($ch);

});

?>
===DONE===
--EXPECTF--
array(1) {
  ["test"]=>
  string(7) "getpost"
}
array(0) {
}
array(1) {
  ["test"]=>
  string(7) "getpost"
}
array(0) {
}
array(1) {
  ["test"]=>
  string(7) "getpost"
}
array(2) {
  ["id"]=>
  string(3) "123"
  ["name"]=>
  string(6) "swoole"
}
array(1) {
  ["test"]=>
  string(7) "getpost"
}
array(2) {
  ["id"]=>
  string(3) "123"
  ["name"]=>
  string(6) "swoole"
}
===DONE===
