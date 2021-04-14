--TEST--
swoole_curl/setopt: CURLOPT_INFILE
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new \SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = 'http://' . HTTPBIN_SERVER_HOST . ':' . HTTPBIN_SERVER_PORT . '/put';
    $fp = fopen(__FILE__, "r");
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_USERPWD, 'user:password');
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PUT, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_INFILE, $fp);
    curl_setopt($ch, CURLOPT_INFILESIZE, filesize(__FILE__));
    $http_result = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    var_dump($http_code);
    $http_body = json_decode($http_result, true);
    var_dump($http_body['headers']['Authorization']);
    Assert::same($http_body['data'], file_get_contents(__FILE__));
    curl_close($ch);
    fclose($fp);
});

?>
--EXPECT--
int(200)
string(26) "Basic dXNlcjpwYXNzd29yZA=="
