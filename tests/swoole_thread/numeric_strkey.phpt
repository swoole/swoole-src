--TEST--
swoole_thread: numeric key
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php

use Swoole\Thread\Map;

require __DIR__ . '/../include/bootstrap.php';
$uuid = uniqid();

const I_KEY = 6666;
const S_KEY = '6666';

$arr = new Map([S_KEY => 2222, 'test' => $uuid]);
Assert::eq($arr[S_KEY], 2222);
Assert::eq($arr[6666], 2222);
Assert::eq($arr['test'], $uuid);

unset($arr[S_KEY]);
Assert::false(isset($arr[S_KEY]));
Assert::keyNotExists($arr->toArray(), I_KEY);

$uuid2 = uniqid();
$arr[6666.66] = $uuid2;
$arr['6666.66'] = $uuid2;
Assert::eq($arr[6666], $uuid2);

$arr[true] = $uuid2;
$arr[false] = $uuid2;
$arr[null] = $uuid2;

$stream = fopen('php://stdin', 'r+');
@$arr[$stream] = $uuid2;

Assert::eq($arr[true], $uuid2);
Assert::eq($arr[false], $uuid2);
Assert::eq($arr[null], $uuid2);
Assert::eq(@$arr[$stream], $uuid2);

?>
--EXPECTF--
