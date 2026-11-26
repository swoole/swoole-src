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
        $intermediate = 'intermediate response larger than the selected response';
        $cases = [
            'connect-failure' => [[200, 'payload']],
            '502' => [[502, $intermediate], [200, 'payload']],
            '503' => [[503, $intermediate], [200, 'payload']],
            '503-empty' => [[503, ''], [200, 'payload']],
            'empty-success' => [[503, $intermediate], [200, '']],
            'exhausted' => [[503, $intermediate], [503, 'failure']],
            'overwrite' => [[503, $intermediate], [200, 'payload']],
        ];
        foreach ($cases as $case => $responses) {
            foreach ([0, 8] as $offset) {
                if ($case === 'connect-failure') {
                    $resolver->attempts = 0;
                }
                $initial = $case === 'overwrite' ? 'original1234567890' : 'original';
                file_put_contents($filename, $initial);
                Coroutine::create(function () use ($listener, $responses, $filename, $initial) {
                    foreach ($responses as $index => [$status, $payload]) {
                        $peer = $listener->accept(2);
                        Assert::true($peer instanceof Socket);
                        $request = '';
                        while (!str_contains($request, "\r\n\r\n")) {
                            $data = $peer->recv(8192, 2);
                            Assert::notEmpty($data);
                            $request .= $data;
                        }
                        if ($index > 0) {
                            Assert::same(file_get_contents($filename), $initial);
                        }
                        $length = strlen($payload);
                        $response = "HTTP/1.1 $status Status\r\nConnection: close\r\nContent-Length: $length\r\n\r\n$payload";
                        Assert::same($peer->sendAll($response), strlen($response));
                        $peer->close();
                    }
                });
                $client = new Client($case === 'connect-failure' ? 'download.service' : '127.0.0.1',
                    $case === 'connect-failure' ? 0 : $port);
                $client->set(['timeout' => 2, 'connect_timeout' => 0.1, 'max_retries' => 1]);
                Assert::same($client->download('/', $filename, $offset), $case !== 'exhausted');
                [, $payload] = end($responses);
                $expected = match (true) {
                    $payload === '' => $initial,
                    $offset === 0 => $payload,
                    default => substr_replace($initial, $payload, $offset, strlen($payload)),
                };
                Assert::same(file_get_contents($filename), $expected, $case);
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
