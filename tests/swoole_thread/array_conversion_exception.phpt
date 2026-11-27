--TEST--
swoole_thread: failed serialization during array conversion preserves values, markers and locks
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

class ArrayConversionValue
{
    public bool $fail = true;
    public function __serialize(): array
    {
        if ($this->fail) {
            throw new RuntimeException('conversion failed');
        }
        return ['fail' => false];
    }
}
function expectConversionError(callable $operation): void
{
    try {
        $operation();
        Assert::true(false, 'Serialization failure must be propagated');
    } catch (RuntimeException $exception) {
        Assert::same($exception->getMessage(), 'conversion failed');
    }
}

$value = new ArrayConversionValue();
$source = ['prefix' => str_repeat('x', 1024), 'bad' => $value];
$map = new Map(['keep' => 'old', 1 => 'old']);
foreach (['keep', 1] as $key) {
    expectConversionError(function () use ($map, $key, $source) { $map[$key] = $source; });
    expectConversionError(fn() => $map->update($key, $source));
    expectConversionError(fn() => $map->add(is_int($key) ? 2 : 'new', $source));
}
Assert::same($map->toArray(), ['keep' => 'old', 1 => 'old']);
Assert::true($map->update('keep', 'updated'));
$list = new ArrayList(['old']);
expectConversionError(function () use ($list, $source) { $list[] = $source; });
Assert::same($list->toArray(), ['old']);
$queue = new Queue();
expectConversionError(fn() => $queue->push($source, Queue::NOTIFY_ONE));
Assert::same(count($queue), 0);

// Retry conversion of the same source after a non-recursive failure.
$value->fail = false;
$copy = new Map($source);
Assert::same($copy['prefix'], $source['prefix']);
Assert::false($copy['bad']->fail);
// Objects retain PHP serialization's reference handling, including a reference back to this source array.
$object = new stdClass();
$withObject = ['object' => $object];
$object->source = &$withObject;
$copy = new Map($withObject);
$restored = $copy['object'];
Assert::same($restored->source['object'], $restored);
echo "DONE\n";
?>
--EXPECT--
DONE
