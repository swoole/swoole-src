<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);
$str = 'hello world';
var_dump($str->upper());

var_dump($str->split(' ')->search('world'));
var_dump($str->length());
var_dump('test'->length());

var_dump($str->indexOf('world'));
var_dump($str->substr(1, 4));

var_dump($str->startsWith('hello'));
var_dump($str->endsWith('world'));
var_dump($str->endsWith('.php'));

var_dump($str->md5(), $str->sha1(), $str->crc32());
var_dump($str->hash('sha256'));
echo "==============================hash=====================\n";
var_dump($str->md5() === $str->hash('md5'));

$str = 'first=value&arr[]=foo+bar&arr[]=baz';
$output = $str->parseStr();
echo $output['first'];  // value
echo $output['arr'][0]; // foo bar
echo $output['arr'][1]; // baz

var_dump($str->urlEncode());
