--TEST--
swoole_curl/setopt: CURLOPT_NOBODY
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
/*
 * Prototype:     bool curl_setopt_array(resource $ch, array $options)
 * Description:   Sets multiple options for a cURL session.
 * Source:        ext/curl/interface.c
 * Documentation: http://wiki.php.net/qa/temp/ext/curl
 */

require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "{$host}/get.php?test=get";

    $ch = curl_init();

    $options = array(
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_NOBODY => true,
    );

    curl_setopt_array($ch, $options);
    $returnContent = curl_exec($ch);
    Assert::isEmpty($returnContent);
    curl_close($ch);
    echo "END\n";
});

?>
--EXPECT--
END
