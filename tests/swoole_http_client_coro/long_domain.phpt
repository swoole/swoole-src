--TEST--
swoole_http_client_coro: long domain
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$domains = [
    str_repeat('8', 63) . '.test',
    'www.' . str_repeat('a', 63) . '.test',
    implode('.', array_fill(0, 3, str_repeat('b', 63))) . '.test',
];
$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $domains) {
    Co\run(function () use ($pm, $domains) {
        $resolver = new class($pm->getFreePort()) extends Swoole\NameResolver {
            public array $lookups = [];

            public function __construct(private int $port)
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

            public function getCluster(string $name): ?Swoole\NameResolver\Cluster
            {
                return null;
            }

            public function lookup(string $name)
            {
                $this->lookups[] = $name;
                return ['host' => '127.0.0.1', 'port' => $this->port];
            }
        };
        Assert::true(swoole_name_resolver_add($resolver));
        try {
            foreach ($domains as $domain) {
                $client = new Co\Http\Client($domain, $pm->getFreePort());
                $client->set(['timeout' => 2]);
                $client->setHeaders(['Host' => $domain]);
                Assert::true($client->get('/'));
                Assert::same($client->statusCode, 200);
                Assert::same($client->body, $domain);
                $client->close();
            }
            Assert::same($resolver->lookups, $domains);
        } finally {
            swoole_name_resolver_remove($resolver);
        }
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('Request', function ($request, $response) { $response->end($request->header['host']); });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
