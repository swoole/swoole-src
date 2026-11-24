--TEST--
swoole_http_client_coro: advertise all compiled response codings without overriding caller preferences
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$codings = [];
if (defined('SWOOLE_HAVE_ZLIB')) {
    $codings = ['gzip', 'deflate'];
}
if (defined('SWOOLE_HAVE_BROTLI')) {
    $codings[] = 'br';
}
ob_start();
(new ReflectionExtension('swoole'))->info();
$moduleInfo = ob_get_clean();
if (defined('SWOOLE_HAVE_ZSTD') || preg_match('/^zstd => /m', $moduleInfo)) {
    $codings[] = 'zstd';
}
$automatic = $codings ? implode(', ', $codings) : null;
$cases = [[[], [], $automatic], [['http_compression' => false], [], null],
    [['http_compression' => true], [], $automatic]];
if ($codings) {
    $cases[] = [[], ['aCcEpT-EnCoDiNg' => 'identity'], 'identity'];
    $cases[] = [[], ['Accept-Encoding' => ''], ''];
    $cases[] = [['http_compression' => false], ['Accept-Encoding' => 'gzip;q=0.5, identity;q=1'], 'gzip;q=0.5, identity;q=1'];
}
Coroutine\run(function () use ($cases) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        $listener = http_client_body_listener($ssl);
        Coroutine::create(function () use ($listener, $ssl, $cases) {
            $peer = $listener->accept(5);
            if ($ssl) {
                Assert::true($peer->sslHandshake());
            }
            $buffer = '';
            foreach ($cases as [$_, $unused, $expected]) {
                $request = http_client_body_headers($peer, $buffer);
                $found = preg_match_all('/^Accept-Encoding: ?([^\r\n]*)\r?$/im', $request['header'], $matches);
                Assert::same($found, $expected === null ? 0 : 1);
                if ($expected !== null) {
                    Assert::same($matches[1][0], $expected);
                }
                http_client_body_reply($peer, 'ok');
            }
            $peer->close();
        });
        $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
        foreach ($cases as [$settings, $headers, $expected]) {
            $client->set($settings + ['timeout' => 5, 'http_compression' => true]);
            $client->setHeaders($headers);
            Assert::true($client->post('/encoding', ''));
            Assert::same($client->body, 'ok');
        }
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
