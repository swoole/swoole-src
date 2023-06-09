--TEST--
swoole_curl/setopt: CURLOPT_FILETIME
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {

    $ch = curl_init();

    $options = array(
        CURLOPT_URL => 'https://static.zhihu.com/heifetz/chunks/5946.4600cc0c1b3dcecac17c.js',
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_FILETIME => true,
        CURLOPT_NOBODY => true,
    );

    curl_setopt_array($ch, $options);
    curl_exec($ch);
    $info = curl_getinfo($ch);
    Assert::assert(!empty($info['filetime']));
    Assert::greaterThanEq($info['filetime'], 1000000);
    curl_close($ch);
    echo "END\n";
}, false);

?>
--EXPECT--
END
