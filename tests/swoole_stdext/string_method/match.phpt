--TEST--
swoole_stdext/string_method: match
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$str = 'foobarbaz';
$regex1 = '/(foo)(bar)(baz)/';
$matches = $str->match($regex1, PREG_OFFSET_CAPTURE);

preg_match($regex1, $str, $matches2, PREG_OFFSET_CAPTURE);
Assert::eq($matches, $matches2);


$html = "<b>bold text</b><a href=howdy.html>click me</a>";
$regex2 = "/(<([\w]+)[^>]*>)(.*?)(<\/\\2>)/";
preg_match_all($regex2, $html, $matches2, PREG_SET_ORDER);

$matches = $html->matchAll($regex2, PREG_SET_ORDER);
Assert::eq($matches, $matches2);

?>
--EXPECT--
