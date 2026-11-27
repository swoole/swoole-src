--TEST--
swoole_socket_coro: concurrent closes wait for cancellation and only the first succeeds
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

Coroutine\run(function () {
    $canceling = new Channel(1);
    $resolver = new class ($canceling) extends NameResolver {
        public function __construct(private Channel $canceling) {}
        public function join(string $name, string $ip, int $port, array $options = []): bool { return true; }
        public function leave(string $name, string $ip, int $port): bool { return true; }
        public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
        public function lookup(string $name) {
            Coroutine::sleep(60);
            // Hold the resolver after cancellation, as a completion backend can do while draining I/O.
            // Defer the acknowledgment so the test resumes only after this coroutine has suspended.
            Swoole\Event::defer(fn () => $this->canceling->push(true));
            Coroutine::suspend();
            return '127.0.0.1';
        }
    };
    Assert::true(swoole_name_resolver_add($resolver));
    try {
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $lookup = Coroutine::create(function () use ($socket) {
            Assert::false($socket->connect('close-barrier.test', 1));
            Assert::same($socket->errCode, SOCKET_ECANCELED);
        });
        $results = new Channel(2);
        $firstReturned = $secondReturned = false;
        $first = Coroutine::create(function () use ($socket, $results, &$firstReturned) {
            $closed = $socket->close();
            $firstReturned = true;
            $results->push([$closed, $socket->errCode]);
        });
        Assert::true($canceling->pop(3));
        $second = Coroutine::create(function () use ($socket, $results, &$secondReturned) {
            $closed = $socket->close();
            $secondReturned = true;
            $results->push([$closed, $socket->errCode]);
        });
        Assert::false($firstReturned);
        Assert::false($secondReturned);
        Assert::false($socket->isClosed());
        Assert::false(Coroutine::cancel($first));
        Assert::false(Coroutine::cancel($second));
        // PHP resume() must reject a native close barrier; C++ tests also exercise direct early resume.
        Assert::false(@Coroutine::resume($second));
        Assert::false($secondReturned);
        Assert::true(Coroutine::resume($lookup));
        Assert::same($results->pop(3), [true, 0]);
        Assert::same($results->pop(3), [false, SOCKET_EBADF]);
        Assert::true($socket->isClosed());
        Assert::false($socket->close());
        Assert::same($socket->errCode, SOCKET_EBADF);
    } finally {
        swoole_name_resolver_remove($resolver);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
