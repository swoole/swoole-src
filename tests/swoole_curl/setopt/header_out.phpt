--TEST--
swoole_curl/setopt: CURLINFO_HEADER_OUT
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
    $url = "{$host}/post.php?test=get";

    $ch = curl_init();

    $options = array(
        CURLOPT_URL => $url,
        CURLINFO_HEADER_OUT => true,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_POST => 1,
        CURLOPT_POSTFIELDS => 'id=123&name=swoole',
    );

    curl_setopt_array($ch, $options);
    $returnContent = curl_exec($ch);
    Assert::assert($returnContent);
    $info = curl_getinfo($ch);
    Assert::assert($info['request_header']);
    curl_close($ch);
    echo "END\n";
});

?>
--EXPECT--
END
