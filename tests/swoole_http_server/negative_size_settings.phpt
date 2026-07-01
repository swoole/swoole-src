--TEST--
swoole_http_server: negative size settings
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$errors = [];
set_error_handler(function (int $errno, string $errstr) use (&$errors) {
    $errors[] = $errstr;
    return true;
});

$server = new Swoole\Http\Server('127.0.0.1', get_one_free_port());
$server->set([
    'compression_min_length' => -1,
    'upload_max_filesize' => -1,
]);

restore_error_handler();

Assert::eq(count($errors), 2);
Assert::contains($errors[0], 'compression_min_length');
Assert::contains($errors[1], 'upload_max_filesize');

echo "DONE\n";
?>
--EXPECT--
DONE
