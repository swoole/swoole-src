--TEST--
swoole_library/name_resolver: lookup
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;

use function Swoole\Coroutine\run;

$config = TEST_NAME_RESOLVER;
$ns = new $config['class']($config['server_url']);
Coroutine::set(['name_resolver' => [$ns]]);

const N = 4;

run(function () use ($ns) {
    $test_name = 'test_resolver_1';
    $nodes = [];
    swoole_loop_n(N, function () use (&$nodes, $test_name, $ns) {
        $node = ['port' => rand(1, 9999), 'ip' => '192.168.1.' . rand(1, 255)];
        $nodes[] = $node;
        $ns->join($test_name, $node['ip'], $node['port']);
    });

    $ctx = new Swoole\NameResolver\Context(AF_INET, true);
    swoole_loop_n(N * 2, function ($i) use (&$nodes, $test_name, $ns, $ctx) {
        $rs = swoole_name_resolver_lookup($test_name, $ctx);
        Assert::notEmpty($rs);
        [$ip, $port] = explode(':', $rs);
        $node = ['ip' => $ip, 'port' => $port];
        Assert::true(in_array($node, $nodes));
    });

    swoole_loop_n(N, function ($i) use (&$nodes, $test_name, $ns) {
        $ns->leave($test_name, $nodes[$i]['ip'], $nodes[$i]['port']);
    });
});
echo "DONE\n";
?>
--EXPECTF--
DONE
