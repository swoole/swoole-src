--TEST--
NameResolver: PHP threads isolate resolver objects and request cleanup
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
if (!class_exists(Swoole\Thread::class)) die('skip thread support required');
?>
--FILE--
<?php
function same($actual, $expected): void {
    if ($actual !== $expected) {
        throw new RuntimeException(var_export([$actual, $expected], true));
    }
}
class ThreadResolver extends Swoole\NameResolver {
    public function __construct(private string $ip) {}
    public function join(string $name, string $ip, int $port, array $options = []): bool { return true; }
    public function leave(string $name, string $ip, int $port): bool { return true; }
    public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
    public function lookup(string $name) {
        Swoole\Coroutine::sleep(0.001);
        return $this->ip;
    }
}
$args = Swoole\Thread::getArguments();
if ($args) {
    [$ip, $ready, $release] = $args;
    Swoole\Coroutine\run(function () use ($ip, $ready, $release) {
        same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), '127.0.0.1');
        $resolver = new ThreadResolver($ip);
        same(swoole_name_resolver_add($resolver), true);
        $ready->add();
        while (!$release->get()) Swoole\Coroutine::sleep(0.001);
        for ($i = 0; $i < 8; $i++) {
            same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), $ip);
        }
        // RSHUTDOWN removes only this thread's resolver, without an explicit remove().
    });
} else {
    $resolver = new ThreadResolver('127.0.0.10');
    same(swoole_name_resolver_add($resolver), true);
    $ready = new Swoole\Thread\Atomic(0);
    $release = new Swoole\Thread\Atomic(0);
    $threads = [];
    foreach (['127.0.0.11', '127.0.0.12'] as $ip) {
        $threads[] = new Swoole\Thread(__FILE__, $ip, $ready, $release);
    }
    Swoole\Coroutine\run(function () use ($ready, $release) {
        $deadline = microtime(true) + 5;
        while ($ready->get() !== 2 && microtime(true) < $deadline) Swoole\Coroutine::sleep(0.001);
        $release->set(1);
        same($ready->get(), 2);
        for ($i = 0; $i < 8; $i++) {
            same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), '127.0.0.10');
        }
    });
    foreach ($threads as $thread) {
        same($thread->join(), true);
        same($thread->getExitStatus(), 0);
    }
    Swoole\Coroutine\run(function () {
        same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), '127.0.0.10');
    });
    same(swoole_name_resolver_remove($resolver), true);
    echo "DONE\n";
}
?>
--EXPECT--
DONE
