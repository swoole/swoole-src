--TEST--
swoole_http_client_coro: #2661 reject overlapping requests during name resolution and allow cross close
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\NameResolver;
use Swoole\NameResolver\Cluster;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', fn ($request, $response) => $response->end('OK'));
    Coroutine::create(fn () => $server->start());

    $resolver = new class extends NameResolver {
        public int $lookups = 0;

        public function __construct()
        {
        }

        public function join(string $name, string $ip, int $port, array $options = []): bool
        {
            return true;
        }

        public function leave(string $name, string $ip, int $port): bool
        {
            return true;
        }

        public function getCluster(string $name): ?Cluster
        {
            return null;
        }

        public function lookup(string $name): string
        {
            if (++$this->lookups === 1) {
                // Suspend the first lookup until close interrupts it.
                Coroutine::sleep(5);
                return '';
            }
            return '127.0.0.1';
        }
    };
    Assert::true(swoole_name_resolver_add($resolver));
    $client = new Client('overlap.test', $server->port);
    $client->set(['timeout' => 2]);
    $done = new Channel(1);
    $request = Coroutine::create(fn () => $done->push([$client->get('/first')]));
    try {
        Assert::same($resolver->lookups, 1);
        Assert::false($client->get('/overlapping'));
        Assert::same($client->errCode, SOCKET_EBUSY);
        Assert::same($resolver->lookups, 1);

        $client->close();
        Assert::same($done->pop(2), [false]);
        Assert::false($client->connected);

        Assert::true($client->get('/after-close'));
        Assert::same($client->body, 'OK');
    } finally {
        if (Coroutine::exists($request)) {
            Coroutine::cancel($request);
        }
        $client->close();
        swoole_name_resolver_remove($resolver);
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
