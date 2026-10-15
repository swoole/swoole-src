--TEST--
NameResolver: coroutine registry mutation and active Context lifetime are safe
--SKIPIF--
<?php if (!extension_loaded('swoole')) die('skip swoole required'); ?>
--FILE--
<?php
function check($value): void { if (!$value) throw new RuntimeException('Assertion failed'); }
Swoole\Coroutine::set(['hook_flags' => 0]);
Swoole\Coroutine\run(function () {
    $entered = new Swoole\Coroutine\Channel(1);
    $resume = new Swoole\Coroutine\Channel(1);
    $result = new Swoole\Coroutine\Channel(1);
    $resolver = new class($entered, $resume) extends Swoole\NameResolver {
        public function __construct(private $entered, private $resume) {}
        public function join(string $name, string $ip, int $port, array $options=[]): bool { return true; }
        public function leave(string $name, string $ip, int $port): bool { return true; }
        public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
        public function lookup(string $name) {
            $this->entered->push(true);
            $this->resume->pop(2);
            return '127.0.0.2';
        }
    };
    check(swoole_name_resolver_add($resolver));
    $ctx = new Swoole\NameResolver\Context();
    Swoole\Coroutine::create(fn() => $result->push(swoole_name_resolver_lookup('service', $ctx)));
    check($entered->pop(2));
    try {
        swoole_name_resolver_lookup('service', $ctx);
        throw new RuntimeException('Concurrent Context was accepted');
    } catch (Error $e) {
        check($e->getMessage() === 'NameResolver Context is already in use');
    }
    try {
        $ctx->__construct();
        throw new RuntimeException('Active Context was reset');
    } catch (Error $e) {
        check($e->getMessage() === 'NameResolver Context is already in use');
    }
    $weak = WeakReference::create($resolver);
    check(swoole_name_resolver_remove($resolver));
    unset($resolver);
    check($weak->get() !== null);
    $resume->push(true);
    check($result->pop(2) === '127.0.0.2');
    // A retained Context must release the removed resolver before the next lookup.
    check(swoole_name_resolver_lookup('localhost', $ctx) === '127.0.0.1');
    check($weak->get() === null);
});
echo "DONE\n";
?>
--EXPECT--
DONE
