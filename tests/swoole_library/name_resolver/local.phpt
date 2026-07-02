--TEST--
swoole_library/name_resolver: local resolver
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

class LocalResolver extends Swoole\NameResolver
{
    public int $calls = 0;

    public function __construct(private mixed $result)
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

    public function lookup(string $name): mixed
    {
        $this->calls++;
        return $this->result;
    }
}

$resolver = new LocalResolver('127.0.0.1');
Assert::true(swoole_name_resolver_add($resolver));
$ctx = new Swoole\NameResolver\Context();
Assert::same(swoole_name_resolver_lookup('local.test', $ctx), '127.0.0.1');
Assert::true(swoole_name_resolver_remove($resolver));
Assert::same($resolver->calls, 1);

$cluster = new Swoole\NameResolver\Cluster();
$cluster->add('127.0.0.2', 9501);
$cluster->add('127.0.0.3', 9502);
$resolver = new LocalResolver($cluster);
Assert::true(swoole_name_resolver_add($resolver));
$ctx = new Swoole\NameResolver\Context(AF_INET, true);
$result = swoole_name_resolver_lookup('cluster.test', $ctx);
Assert::contains($result, '127.0.0.');
Assert::contains($result, ':950');
Assert::true(swoole_name_resolver_remove($resolver));

$resolver = new LocalResolver(null);
Assert::true(swoole_name_resolver_add($resolver));
$ctx = new Swoole\NameResolver\Context();
Assert::same(swoole_name_resolver_lookup('miss.test', $ctx), '');
Assert::true(swoole_name_resolver_remove($resolver));

echo "DONE\n";
?>
--EXPECT--
DONE
