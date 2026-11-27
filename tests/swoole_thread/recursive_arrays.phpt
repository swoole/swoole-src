--TEST--
swoole_thread: recursive arrays fail without changing shared containers or retaining recursion markers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\ArrayList;
use Swoole\Thread\Map;
use Swoole\Thread\Queue;

function expectRecursionError(callable $operation): void
{
    try {
        $operation();
        Assert::true(false, 'Recursive input must throw ValueError');
    } catch (ValueError $exception) {
        Assert::same($exception->getMessage(), 'Recursive arrays are not supported');
    }
}

$self = ['prefix' => str_repeat('x', 1024)];
$self['self'] = &$self;
$left = [];
$right = ['left' => &$left];
$left['right'] = &$right;

foreach ([$self, $left] as $recursive) {
    expectRecursionError(fn() => new Map($recursive));
    expectRecursionError(fn() => new ArrayList([$recursive]));
    $map = new Map(['keep' => 'old', 1 => 'old']);
    foreach (['keep', 1] as $key) {
        expectRecursionError(function () use ($map, $key, $recursive) { $map[$key] = $recursive; });
        expectRecursionError(fn() => $map->update($key, $recursive));
        expectRecursionError(fn() => $map->add(is_int($key) ? 2 : 'new', $recursive));
        Assert::same($map[$key], 'old');
    }
    Assert::same($map->toArray(), ['keep' => 'old', 1 => 'old']);
    // Conditional operations must not convert values when they have nothing to change.
    Assert::false($map->add('keep', $recursive));
    Assert::false($map->update('missing', $recursive));
    Assert::true($map->update('keep', 'updated'));
    Assert::true($map->add('new', 'added'));
    Assert::true($map->add(2, 'numeric'));
    Assert::false($map->add(2, 'overwritten'));
    Assert::same($map[2], 'numeric');
    Assert::same($map['keep'], 'updated');

    $list = new ArrayList(['old']);
    expectRecursionError(function () use ($list, $recursive) { $list[] = $recursive; });
    expectRecursionError(function () use ($list, $recursive) { $list[0] = $recursive; });
    Assert::same($list->toArray(), ['old']);
    $list[] = 'next';
    Assert::same($list->toArray(), ['old', 'next']);

    $queue = new Queue();
    $queue->push('old');
    foreach ([0, Queue::NOTIFY_ONE, Queue::NOTIFY_ALL] as $notify) {
        expectRecursionError(fn() => $queue->push($recursive, $notify));
        Assert::same(count($queue), 1);
    }
    Assert::same($queue->pop(), 'old');
    $queue->push('next');
    Assert::same($queue->pop(), 'next');
}

// Rejecting the cycle must clear the markers on the very same source array.
unset($self['self']);
Assert::same((new Map($self))->toArray(), $self);
unset($left['right']);
Assert::same((new Map($left))->toArray(), []);

// A repeated acyclic reference is not a cycle.
$leaf = ['n' => 7];
$source = [&$leaf, &$leaf];
$list = new ArrayList($source);
Assert::same($list[0]->toArray(), $leaf);
Assert::same($list[1]->toArray(), $leaf);
Assert::same($source, [['n' => 7], ['n' => 7]]);
Assert::same((new ArrayList([[], []]))->toArray()[0]->toArray(), []);

// Failed construction must release its partial native state and permit later valid construction.
$again = [];
$again['self'] = &$again;
for ($i = 0; $i < 3; ++$i) {
    expectRecursionError(fn() => new Map($again));
}
$map = new Map(['ok' => true]);
Assert::same($map->toArray(), ['ok' => true]);
echo "DONE\n";
?>
--EXPECT--
DONE
