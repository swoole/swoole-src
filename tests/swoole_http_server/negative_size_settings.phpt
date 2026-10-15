--TEST--
swoole_http_server: negative size settings
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$errors = [];
set_error_handler(function (int $errno, string $errstr) use (&$errors) {
    $errors[] = $errstr;
    return true;
});

$server = new Swoole\Http\Server('127.0.0.1', get_one_free_port());
foreach (['compression_min_length', 'upload_max_filesize'] as $option) {
    try {
        $server->set([$option => -1]);
        Assert::true(false, 'negative size must throw');
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::contains($exception->getMessage(), $option);
    }
    Assert::null($server->setting);
}

restore_error_handler();

Assert::same($errors, []);

echo "DONE\n";
?>
--EXPECT--
DONE
