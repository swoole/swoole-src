--TEST--
swoole_coroutine: getContext
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function func(callable $fn, ...$args)
{
    go(function () use ($fn, $args) {
        $fn(...$args);
        echo 'Coroutine#' . Co::getCid() . ' exit' . PHP_EOL;
    });
}

/**
 * Compatibility for lower version
 * @param object|Resource $object
 * @return int
 */
function php_object_id($object)
{
    static $id = 0;
    static $map = [];
    $hash = spl_object_hash($object);
    return $map[$hash] ?? ($map[$hash] = ++$id);
}

class Resource
{
    public function __construct()
    {
        echo __CLASS__ . '#' . php_object_id((object)$this) . ' constructed' . PHP_EOL;
    }

    public function __destruct()
    {
        echo __CLASS__ . '#' . php_object_id((object)$this) . ' destructed' . PHP_EOL;
    }
}

$context = new Co\Context();
Assert::assert($context instanceof ArrayObject);
Assert::assert(Co::getContext() === null);
func(function () {
    $context = Co::getContext();
    Assert::assert($context instanceof Co\Context);
    $context['resource1'] = new Resource;
    $context->resource2 = new Resource;
    func(function () {
        Co::getContext()['resource3'] = new Resource;
        Co::yield();
        Co::getContext()['resource3']->resource4 = new Resource;
        Co::getContext()->resource5 = new Resource;
    });
});
Co::resume(2);
?>
--EXPECT--
Resource#1 constructed
Resource#2 constructed
Resource#3 constructed
Coroutine#1 exit
Resource#2 destructed
Resource#1 destructed
Resource#4 constructed
Resource#5 constructed
Coroutine#2 exit
Resource#5 destructed
Resource#3 destructed
Resource#4 destructed
