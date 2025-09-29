--TEST--
swoole_thread: add/update
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\Map;

const KEY_EXISTS = 'exists';
const KEY_NOT_EXISTS = 'not_exists';

const INDEX_EXISTS = 1000;
const INDEX_NOT_EXISTS = 9999;

$value = random_bytes(32);

$m = new Map();
$m[KEY_EXISTS] = $value;

Assert::false($m->update(KEY_NOT_EXISTS, $value));
Assert::true($m->add(KEY_NOT_EXISTS, $value));
Assert::eq($m[KEY_NOT_EXISTS], $value);

unset($m[KEY_NOT_EXISTS]);
Assert::eq($m[KEY_NOT_EXISTS], null);

Assert::false($m->add(KEY_EXISTS, $value));
Assert::true($m->update(KEY_EXISTS, $value));
Assert::eq($m[KEY_EXISTS], $value);

$m2 = new Map();
$m2[INDEX_EXISTS] = $value;

Assert::false($m2->update(INDEX_NOT_EXISTS, $value));
Assert::true($m2->add(INDEX_NOT_EXISTS, $value));
Assert::eq($m2[INDEX_NOT_EXISTS], $value);

unset($m2[INDEX_NOT_EXISTS]);
Assert::eq($m2[INDEX_NOT_EXISTS], null);

Assert::false($m2->add(INDEX_EXISTS, $value));
Assert::true($m2->update(INDEX_EXISTS, $value));
Assert::eq($m2[INDEX_EXISTS], $value);

?>
--EXPECTF--
