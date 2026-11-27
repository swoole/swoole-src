--TEST--
swoole_http_client_coro: multipart field conversions are shared by length, sends and retries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $server = new Server('127.0.0.1', 0, $tls);
        if ($tls) {
            $server->set([
                'ssl_cert_file' => __DIR__ . '/../include/ssl_certs/server.crt',
                'ssl_key_file' => __DIR__ . '/../include/ssl_certs/server.key',
            ]);
        }
        $attempts = 0;
        $server->handle('/', function ($request, $response) use (&$attempts) {
            Assert::same($request->post, ['field' => 'first', 'string' => 'fixed', 'empty' => '']);
            Assert::same(file_get_contents($request->files['upload']['tmp_name']), 'file');
            ++$attempts;
            $response->status($attempts === 1 ? 503 : 200);
            $response->header('Connection', 'close');
            $response->end('done');
        });
        Coroutine::create(fn () => $server->start());
        $client = new Client('127.0.0.1', $server->port, $tls);
        $client->set(['timeout' => 2, 'max_retries' => 1]);
        $value = new class {
            public int $calls = 0;
            public function __toString(): string
            {
                // Exercise the lifetime of the snapshot across coroutine switches as well.
                Coroutine::sleep(0.001);
                return ++$this->calls === 1 ? 'first' : 'changed and much longer';
            }
        };
        try {
            $client->addData('file', 'upload', 'text/plain', 'file.txt');
            $fields = ['field' => $value, 'string' => 'fixed', 'empty' => '', 'null' => null];
            Assert::true($client->post('/', $fields));
            Assert::same($attempts, 2);
            Assert::same($value->calls, 1);
            Assert::same($fields['field'], $value);
            Assert::same($client->body, 'done');

            $client->addData('file', 'upload', 'text/plain', 'file.txt');
            $throwing = new class {
                public function __toString(): string { throw new RuntimeException('conversion failed'); }
            };
            try {
                $client->post('/', ['field' => $throwing]);
                Assert::true(false, 'the conversion exception must propagate');
            } catch (RuntimeException $exception) {
                Assert::same($exception->getMessage(), 'conversion failed');
            }
            Assert::same($attempts, 2);
        } finally {
            $client->close();
            $server->shutdown();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
