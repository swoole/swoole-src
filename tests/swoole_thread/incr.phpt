--TEST--
swoole_thread: incr/decr
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

const KEY_EXISTS_LVAL = 'exists_lval';
const KEY_EXISTS_DVAL = 'exists_dval';
const KEY_NOT_EXISTS_LVAL = 'not_exists_lval';
const KEY_NOT_EXISTS_DVAL = 'not_exists_dval';

$init_lval = random_int(1, 999999999999999999);
$init_dval = random_int(1, 999999999999999999) / 13.03;

$add_lval = random_int(1, 88888888);
$add_dval = random_int(1, 88888888) / 17.07;

$m = new Map();
$m[KEY_EXISTS_LVAL] = $init_lval;
$m[KEY_EXISTS_DVAL] = $init_dval;
$l = new ArrayList();

Assert::eq($m->incr(KEY_NOT_EXISTS_LVAL), 1);
Assert::eq($m[KEY_NOT_EXISTS_LVAL], 1);

Assert::eq($m->incr(KEY_NOT_EXISTS_DVAL, $add_dval), $add_dval);
Assert::eq($m[KEY_NOT_EXISTS_DVAL], $add_dval);

Assert::eq($m->incr(KEY_EXISTS_LVAL), $init_lval + 1);
Assert::eq($m[KEY_EXISTS_LVAL], $init_lval + 1);

Assert::eq($m->incr(KEY_EXISTS_DVAL), $init_dval + 1);
Assert::eq($m[KEY_EXISTS_DVAL], $init_dval + 1);

// clean
$m[KEY_EXISTS_LVAL] = $init_lval;
$m[KEY_EXISTS_DVAL] = $init_dval;
unset($m[KEY_NOT_EXISTS_DVAL], $m[KEY_NOT_EXISTS_LVAL]);

Assert::eq($m->incr(KEY_EXISTS_LVAL, $add_lval), $init_lval + $add_lval);
Assert::eq($m[KEY_EXISTS_LVAL], $init_lval + $add_lval);

Assert::eq($m->incr(KEY_EXISTS_DVAL, $add_lval), $init_dval + $add_lval);
Assert::eq($m[KEY_EXISTS_DVAL], $init_dval + $add_lval);

Assert::eq($m->decr(KEY_NOT_EXISTS_LVAL), -1);
Assert::eq($m[KEY_NOT_EXISTS_LVAL], -1);

$m[KEY_EXISTS_LVAL] = $init_lval;
$m[KEY_EXISTS_DVAL] = $init_dval;

Assert::eq($m->decr(KEY_EXISTS_LVAL, $add_lval), $init_lval - $add_lval);
Assert::eq($m[KEY_EXISTS_LVAL], $init_lval - $add_lval);

Assert::eq($m->decr(KEY_EXISTS_DVAL, $add_lval), $init_dval - $add_lval);
Assert::eq($m[KEY_EXISTS_DVAL], $init_dval - $add_lval);

Assert::eq($l->incr(0), 1);
Assert::eq($l[0], 1);

Assert::eq($l->incr(1, $add_lval), $add_lval);
Assert::eq($l[1], $add_lval);

$l[0] = 0;
$l[1] = 0;

Assert::eq($l->incr(0, $add_dval), intval($add_dval));

?>
--EXPECTF--
