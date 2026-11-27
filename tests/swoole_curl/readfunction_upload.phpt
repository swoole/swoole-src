--TEST--
swoole_curl: PHP hook uses CURLOPT_READFUNCTION for the upload body
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Curl\Handler;
use Swoole\Runtime;
use SwooleTest\Assert;

Assert::setThrowException(true);
Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    $requests = 0;
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use (&$requests) {
        ++$requests;
        if ($request->server['request_uri'] === '/redirect') {
            $response->status(307);
            $response->header('Location', '/');
        }
        $response->end($request->getContent());
    });
    Coroutine::create(fn () => $server->start());

    $url = 'http://127.0.0.1:' . $server->port;
    $infile = fopen('php://memory', 'w+b');
    fwrite($infile, 'SRC');
    rewind($infile);
    $curl = curl_init($url . '/redirect');
    Assert::isInstanceOf($curl, Handler::class);
    $opts = [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
        CURLOPT_HTTPHEADER => ['Expect:']];
    try {
        $chunks = ["A\0", 'B'];
        $requested = [];
        curl_setopt_array($curl, $opts + [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_UPLOAD => true,
            CURLOPT_INFILE => $infile,
            CURLOPT_INFILESIZE => 3,
            CURLOPT_READFUNCTION => function ($handle, $input, $length) use ($curl, $infile, &$chunks, &$requested, &$requests) {
                Assert::same($handle, $curl);
                Assert::same($input, $infile);
                Assert::same($requests, 0);
                $requested[] = $length;
                return array_shift($chunks);
            },
        ]);
        Assert::same(curl_exec($curl), "A\0B");
        Assert::same($requested, [3, 1]);
        Assert::same($requests, 2);
        Assert::same(ftell($infile), 0);

        curl_reset($curl);
        $chunks = ['generated', ' body', ''];
        curl_setopt_array($curl, $opts + [
            CURLOPT_URL => $url . '/',
            CURLOPT_POST => true,
            CURLOPT_READFUNCTION => function ($handle, $input, $length) use (&$chunks) {
                Assert::null($input);
                Assert::greaterThan($length, 0);
                return array_shift($chunks);
            },
        ]);
        Assert::same(curl_exec($curl), 'generated body');
        Assert::same($chunks, []);

        curl_setopt($curl, CURLOPT_POSTFIELDS, 'literal');
        curl_setopt($curl, CURLOPT_READFUNCTION, function () {
            throw new RuntimeException('POSTFIELDS supplies the body');
        });
        Assert::same(curl_exec($curl), 'literal');

        curl_reset($curl);
        curl_setopt_array($curl, $opts + [
            CURLOPT_URL => $url . '/', CURLOPT_UPLOAD => true, CURLOPT_INFILESIZE => 3,
            CURLOPT_READFUNCTION => static fn () => 0x10000000, // CURL_READFUNC_ABORT
        ]);
        Assert::false(curl_exec($curl));
        Assert::same(curl_errno($curl), CURLE_ABORTED_BY_CALLBACK);
        Assert::same($requests, 4);

        curl_setopt($curl, CURLOPT_READFUNCTION, static fn () => '');
        Assert::false(curl_exec($curl));
        Assert::same(curl_errno($curl), CURLE_READ_ERROR);
        Assert::same($requests, 4);
    } finally {
        fclose($infile);
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
