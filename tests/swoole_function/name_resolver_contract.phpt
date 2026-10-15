--TEST--
NameResolver: node results, context isolation, finite retries and exception propagation
--SKIPIF--
<?php if (!extension_loaded('swoole')) die('skip swoole required'); ?>
--FILE--
<?php
function same($actual, $expected): void {
    if ($actual !== $expected) {
        throw new RuntimeException(var_export([$actual, $expected], true));
    }
}
function resolver(callable $lookup): Swoole\NameResolver {
    return new class($lookup) extends Swoole\NameResolver {
        private $callback;
        public function __construct(callable $lookup) { $this->callback = $lookup; }
        public function join(string $name, string $ip, int $port, array $options = []): bool { return true; }
        public function leave(string $name, string $ip, int $port): bool { return true; }
        public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
        public function lookup(string $name) { return ($this->callback)($name); }
    };
}
function check(callable $lookup, callable $test): void {
    $resolver = resolver($lookup);
    same(swoole_name_resolver_add($resolver), true);
    try { $test(); } finally { same(swoole_name_resolver_remove($resolver), true); }
}
check(fn() => ['host' => '127.0.0.2', 'port' => 8080], function () {
    same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), '127.0.0.2');
    same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context(AF_INET, true)), '127.0.0.2:8080');
});
check(fn() => ['host' => '::1', 'port' => 8081], function () {
    same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context(AF_INET6, true)), '::1@8081');
    same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context(AF_INET)), '');
});
$calls = 0;
check(function ($name) use (&$calls) {
    $calls++;
    $cluster = new Swoole\NameResolver\Cluster();
    $cluster->add($name === 'first' ? '127.0.0.2' : '127.0.0.3', 8080);
    return $cluster;
}, function () use (&$calls) {
    $ctx = new Swoole\NameResolver\Context();
    same(swoole_name_resolver_lookup('first', $ctx), '127.0.0.2');
    same(swoole_name_resolver_lookup('first', $ctx), '');
    same($calls, 1);
    same(swoole_name_resolver_lookup('second', $ctx), '127.0.0.3');
    same($calls, 2);
});
$shared = new Swoole\NameResolver\Cluster();
$shared->add('127.0.0.4', 8080);
check(fn() => $shared, function () use ($shared) {
    same(swoole_name_resolver_lookup('service', new Swoole\NameResolver\Context()), '127.0.0.4');
    same(swoole_name_resolver_lookup('service', new Swoole\NameResolver\Context()), '127.0.0.4');
    same($shared->count(), 1);
});
check(fn() => null, fn() => same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), '127.0.0.1'));
check(fn() => '', fn() => same(swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()), ''));
check(function () { throw new RuntimeException('registry unavailable'); }, function () {
    try { swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()); }
    catch (RuntimeException $e) { same($e->getMessage(), 'registry unavailable'); return; }
    throw new RuntimeException('Exception was swallowed');
});
foreach ([new stdClass(), 123, ['host' => 'invalid', 'port' => 80], ['host' => '127.0.0.1', 'port' => 70000]] as $invalid) {
    check(fn() => $invalid, function () {
        try { swoole_name_resolver_lookup('localhost', new Swoole\NameResolver\Context()); }
        catch (TypeError|ValueError $e) { return; }
        throw new RuntimeException('Invalid result was accepted');
    });
}
try { swoole_name_resolver_lookup('localhost', new stdClass()); }
catch (TypeError $e) { echo "TYPE OK\n"; }
try { new Swoole\NameResolver\Context(AF_UNIX); }
catch (ValueError $e) { echo "FAMILY OK\n"; }
echo "DONE\n";
?>
--EXPECT--
TYPE OK
FAMILY OK
DONE
