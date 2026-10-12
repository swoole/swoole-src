--TEST--
NameResolver: HTTP client discovers service ports, fails over and preserves Host
--SKIPIF--
<?php if (!extension_loaded('swoole')) die('skip swoole required'); ?>
--FILE--
<?php
function check($value): void { if (!$value) throw new RuntimeException('Assertion failed'); }
Swoole\Coroutine::set(['hook_flags' => 0]);
Swoole\Coroutine\run(function () {
    $listener = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    check($listener->bind('127.0.0.1', 0));
    check($listener->listen());
    $port = $listener->getsockname()['port'];
    // Close the allocated TCP port: BSD may drop SYNs while it remains bound.
    $refused = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    check($refused->bind('127.0.0.1', 0));
    $badPort = $refused->getsockname()['port'];
    $refused->close();
    $hosts = [];
    Swoole\Coroutine::create(function () use ($listener, &$hosts) {
        for ($i = 0; $i < 3; $i++) {
            $connection = $listener->accept(2);
            check($connection !== false);
            $data = '';
            while (!str_contains($data, "\r\n\r\n")) {
                $chunk = $connection->recv(4096, 2);
                check(is_string($chunk) && $chunk !== '');
                $data .= $chunk;
            }
            preg_match('/\r\nHost: ([^\r]+)/i', $data, $matches);
            $hosts[] = $matches[1];
            $connection->sendAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
            $connection->close();
        }
    });
    $resolver = new class($port, $badPort) extends Swoole\NameResolver {
        public array $lookups = [];
        public function __construct(private int $port, private int $badPort) {}
        public function join(string $name, string $ip, int $port, array $options=[]): bool { return true; }
        public function leave(string $name, string $ip, int $port): bool { return true; }
        public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
        public function lookup(string $name) {
            $this->lookups[] = $name;
            if ($name === 'single.service') return ['host' => '127.0.0.1', 'port' => $this->port];
            return new class($this->port, $this->badPort) extends Swoole\NameResolver\Cluster {
                private array $ordered;
                public function __construct(int $port, int $badPort) {
                    $this->ordered = [['host' => '127.0.0.1', 'port' => $badPort], ['host' => '127.0.0.1', 'port' => $port]];
                }
                public function pop(): array|false { return array_shift($this->ordered) ?? false; }
                public function count(): int { return count($this->ordered); }
            };
        }
    };
    check(swoole_name_resolver_add($resolver));
    try {
        foreach (['single.service', 'failover.service', 'failover.service'] as $name) {
            $client = new Swoole\Coroutine\Http\Client($name, 0);
            $client->set(['timeout' => 1, 'max_retries' => 1]);
            check($client->get('/'));
            check($client->body === 'OK');
            $client->close();
        }
        check($hosts === ['single.service', 'failover.service', 'failover.service']);
        check($resolver->lookups === ['single.service', 'failover.service', 'failover.service']);
    } finally {
        swoole_name_resolver_remove($resolver);
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
