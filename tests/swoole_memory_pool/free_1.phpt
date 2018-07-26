--TEST--
swoole_memory_pool: fixed pool free [01]

--SKIPIF--
<?php
require  __DIR__ . '/../include/skipif.inc';
skip_deprecated();
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Memory\Pool;
$pool = new Pool(128 * 1024, Pool::TYPE_FIXED, 1024);
$slices = array();

for ($i = 0; $i < 125; $i++)
{
    /**
     * @var $p1 Swoole\Memory\Pool\Slice
     */
    $p1 = $pool->alloc();
    if ($p1 == false)
    {
        echo "index=$i\n";
        break;
    }
    $p1->write("hello world-" . $i);
    $slices[] = $p1;
}

$p1 = $pool->alloc();
assert($p1 == false);

//free lasest
unset($slices[count($slices) - 1]);
$p1 = $pool->alloc();
assert($p1 != false);
?>
--EXPECT--
