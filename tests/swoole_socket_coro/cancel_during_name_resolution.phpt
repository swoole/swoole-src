--TEST--
swoole_socket_coro: cancel and close use the resolver's cancellation path
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;
use Swoole\NameResolver;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (['read', 'write', 'close'] as $operation) {
        $resolver = new class extends NameResolver {
            public bool $entered = false;
            public bool $canceled = false;
            public function __construct() {}
            public function join(string $name, string $ip, int $port, array $options = []): bool { return true; }
            public function leave(string $name, string $ip, int $port): bool { return true; }
            public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
            public function lookup(string $name) {
                $this->entered = true;
                // Completion backends may yield internally while draining cancellation.
                // The sleep result reports its cancellation independently of those later yields.
                $this->canceled = !Coroutine::sleep(60);
                // Returning an address must not turn a canceled connect into a successful one.
                return '127.0.0.1';
            }
        };
        Assert::true(swoole_name_resolver_add($resolver));
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $finished = new Channel(1);
        $returned = false;
        Coroutine::create(function () use ($socket, $finished, &$returned) {
            Assert::false($socket->connect('socket-cancel.test', 1));
            Assert::same($socket->errCode, SOCKET_ECANCELED);
            $returned = true;
            $finished->push(true);
        });
        try {
            // create() returns after the resolver yields, so no timing delay is needed.
            Assert::true($resolver->entered);
            if ($operation === 'close') {
                Assert::true($socket->close());
            } else {
                Assert::true($socket->cancel($operation === 'read' ? SWOOLE_EVENT_READ : SWOOLE_EVENT_WRITE));
            }
            // cancel() can acknowledge the request before the original completion resumes lookup().
            Assert::true($finished->pop(3));
            Assert::true($resolver->canceled, 'resolver must observe cancellation');
            Assert::true($returned);
        } finally {
            swoole_name_resolver_remove($resolver);
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
