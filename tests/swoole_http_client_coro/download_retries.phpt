--TEST--
swoole_http_client_coro: download targets survive connection and response retries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $port = $listener->getsockname()['port'];
    $refused = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($refused->bind('127.0.0.1', 0));
    $badPort = $refused->getsockname()['port'];
    $refused->close();

    $resolver = new class($port, $badPort) extends Swoole\NameResolver {
        public int $attempts = 0;
        public function __construct(private int $port, private int $badPort)
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
            return new class($this, $this->port, $this->badPort) extends Swoole\NameResolver\Cluster {
                public function __construct(private object $resolver, private int $port, private int $badPort)
                {
                }
                public function pop(): array|false
                {
                    $attempt = $this->resolver->attempts++;
                    return ['host' => '127.0.0.1', 'port' => $attempt === 0 ? $this->badPort : $this->port];
                }
                public function count(): int
                {
                    return 2;
                }
            };
        }
    };
    Assert::true(swoole_name_resolver_add($resolver));
    $filename = tempnam(sys_get_temp_dir(), 'swoole-download-retry-');
    try {
        foreach (['connect-failure', '502', '503', '503-empty', 'exhausted'] as $case) {
            foreach ([0, 8] as $offset) {
                if ($case === 'connect-failure') {
                    $resolver->attempts = 0;
                }
                $statuses = match ($case) {
                    'connect-failure' => [200],
                    '502' => [502, 200],
                    '503', '503-empty' => [503, 200],
                    'exhausted' => [503, 503],
                };
                Coroutine::create(function () use ($listener, $statuses, $case) {
                    foreach ($statuses as $status) {
                        $peer = $listener->accept(2);
                        Assert::true($peer instanceof Socket);
                        $request = '';
                        while (!str_contains($request, "\r\n\r\n")) {
                            $data = $peer->recv(8192, 2);
                            Assert::notEmpty($data);
                            $request .= $data;
                        }
                        $payload = $status === 200 ? 'payload' : ($case === '503-empty' ? '' : 'failure');
                        $length = strlen($payload);
                        $response = "HTTP/1.1 $status Status\r\nConnection: close\r\nContent-Length: $length\r\n\r\n$payload";
                        Assert::same($peer->sendAll($response), strlen($response));
                        $peer->close();
                    }
                });
                file_put_contents($filename, 'original');
                $client = new Client($case === 'connect-failure' ? 'download.service' : '127.0.0.1',
                    $case === 'connect-failure' ? 0 : $port);
                $client->set(['timeout' => 2, 'connect_timeout' => 0.1, 'max_retries' => 1]);
                Assert::same($client->download('/', $filename, $offset), $case !== 'exhausted');
                $expected = $case === 'exhausted' ? 'failure' : 'payload';
                Assert::same(file_get_contents($filename), ($offset === 0 ? '' : 'original') . $expected);
                Assert::null($client->downloadFile);
                Assert::same($client->downloadOffset, 0);
                $client->close();
            }
        }
        Assert::same($resolver->attempts, 2);
    } finally {
        swoole_name_resolver_remove($resolver);
        $listener->close();
        unlink($filename);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
