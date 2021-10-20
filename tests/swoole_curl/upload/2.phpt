--TEST--
swoole_curl/upload: CURL file uploading
--INI--
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://httpbin.org/anything");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $file = new CurlFile(TEST_IMAGE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, array("swoole_file" => $file));
    $result = curl_exec($ch);
    Assert::notEmpty($result);
    $json = json_decode($result);
    Assert::notEmpty($json);
    Assert::notEmpty($json->files->swoole_file);
    $prefix = 'data:application/octet-stream;base64,';
    Assert::startsWith($json->files->swoole_file, $prefix);
    $data = substr($json->files->swoole_file, strlen($prefix));
    Assert::eq(md5(base64_decode($data)), md5_file(TEST_IMAGE));
});
?>
--EXPECTF--
