--TEST--
swoole_http_client_coro: validate stream types, lengths and multipart conflicts before sending
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_upload_stream.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
function body_throws(string $class, callable $operation): void
{
    try {
        $operation();
    } catch (Throwable $exception) {
        Assert::isInstanceOf($exception, $class);
        return;
    }
    throw new RuntimeException('Expected ' . $class);
}

$file = tempnam(sys_get_temp_dir(), 'swoole-body-validation-');
file_put_contents($file, 'file');
try {
    Coroutine\run(function () use ($file) {
        $client = new Client('127.0.0.1', 1);
        $client->setData('unchanged');
        foreach ([null, 1, 1.5, true, new stdClass(), static fn () => 'body'] as $invalid) {
            body_throws(TypeError::class, fn () => $client->setData($invalid));
            Assert::same($client->requestBody, 'unchanged');
        }
        body_throws(TypeError::class, fn () => $client->setData(stream_context_create()));
        $writeOnly = fopen($file, 'ab');
        body_throws(ValueError::class, fn () => $client->setData($writeOnly));
        fclose($writeOnly);
        $directory = opendir(__DIR__);
        body_throws(ValueError::class, fn () => $client->setData($directory));
        closedir($directory);
        $closed = fopen('php://memory', 'w+b');
        fclose($closed);
        body_throws(TypeError::class, fn () => $client->setData($closed));
        foreach (['string', ['key' => 'value']] as $data) {
            body_throws(ValueError::class, fn () => $client->setData($data, 0));
            body_throws(ValueError::class, fn () => $client->setData($data, 1));
            Assert::true($client->setData($data));
        }
        [$source, $state] = HttpClientUploadStream::open(10);
        body_throws(ValueError::class, fn () => $client->setData($source, -1));
        $client->setData($source, 11);
        body_throws(ValueError::class, fn () => $client->execute('/too-long'));
        Assert::false($client->connected);
        Assert::same($state->reads, 0);
        foreach (['addFile', 'addData'] as $add) {
            $client->uploadFiles = null;
            $client->setData($source);
            body_throws(ValueError::class, fn () => $client->$add($add === 'addFile' ? $file : 'content', 'part'));
            $client->setData('raw');
            Assert::true($client->$add($add === 'addFile' ? $file : 'content', 'part'));
            body_throws(ValueError::class, fn () => $client->setData($source));
            Assert::same($client->requestBody, 'raw');
            // Public properties must not bypass conflict checking at execution time.
            $client->requestBody = $source;
            body_throws(ValueError::class, fn () => $client->execute('/conflict'));
            body_throws(ValueError::class, fn () => $client->post('/conflict', $source));
            Assert::false($client->connected);
        }
        $client->uploadFiles = null;
        [$unknown, $unknownState] = HttpClientUploadStream::open(10, false);
        $client->setData($unknown);
        body_throws(ValueError::class, fn () => $client->execute('/unknown-length'));
        Assert::false($client->connected);
        Assert::same($unknownState->reads, 0);
        $client->setData($source);
        fclose($source);
        body_throws(TypeError::class, fn () => $client->execute('/closed'));
        Assert::false($client->connected);
        fclose($unknown);
        $client->close();
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
