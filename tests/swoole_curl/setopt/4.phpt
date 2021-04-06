--TEST--
swoole_curl/setopt: curl_setopt() call with CURLOPT_RETURNTRANSFER
--CREDITS--
Paul Sohier
#phptestfest utrecht
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

// start testing
    echo "*** curl_setopt() call with CURLOPT_RETURNTRANSFER set to 1\n";

    $url = "{$host}/";
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);

    $curl_content = curl_exec($ch);
    curl_close($ch);

    var_dump( $curl_content );

    echo "*** curl_setopt() call with CURLOPT_RETURNTRANSFER set to 0\n";

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 0);
    curl_setopt($ch, CURLOPT_URL, $url);
    ob_start();
    $curl_content = curl_exec($ch);
    ob_end_clean();
    curl_close($ch);

    var_dump( $curl_content );

});

?>
--EXPECTF--
*** curl_setopt() call with CURLOPT_RETURNTRANSFER set to 1
string(%d) "%a"
*** curl_setopt() call with CURLOPT_RETURNTRANSFER set to 0
bool(true)
