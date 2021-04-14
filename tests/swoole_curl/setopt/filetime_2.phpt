--TEST--
swoole_curl/setopt: CURLOPT_FILETIME [return -1]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "{$host}/get.php?test=get";
    $ch = curl_init();

    $options = array(
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_FILETIME => true,
    );

    curl_setopt_array($ch, $options);
    curl_exec($ch);
    $info = curl_getinfo($ch);
    Assert::assert(!empty($info['filetime']));
    Assert::eq($info['filetime'], -1);
    curl_close($ch);
    echo "END\n";
});

?>
--EXPECT--
END
