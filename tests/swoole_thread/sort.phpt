--TEST--
swoole_thread: sort
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\Map;
use Swoole\Thread\ArrayList;

$original_map = array(
    "l" => "lemon",
    "o" => "orange",
    "O" => "Orange",
    "O1" => "Orange1",
    "o2" => "orange2",
    "O3" => "Orange3",
    "o20" => "orange20",
    "b" => "banana",
);

$unsorted_map = new Map($original_map);
$unsorted_map->sort();

$copied_map = $original_map;
asort($copied_map);
Assert::eq($unsorted_map->toArray(), $copied_map);

$original_list =  array( 100, 33, 555, 22 );
$copied_list = $original_list;

$unsorted_list = new ArrayList($original_list);
$unsorted_list->sort();
sort($copied_list);
Assert::eq($unsorted_list->toArray(), $copied_list);
?>
--EXPECT--

