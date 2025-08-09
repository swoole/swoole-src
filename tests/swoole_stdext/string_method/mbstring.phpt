--TEST--
swoole_stdext/string_method: all mbstring methods test
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!extension_loaded("mbstring")) exit("skip mbstring extension not loaded");
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$text = 'bbbb大声向宇宙呐喊bbbb';
Assert::eq($text->mbUpperFirst(), mb_ucfirst($text));

$text = 'Bbbb大声向宇宙呐喊bbbb';
Assert::eq($text->mbLowerFirst(), mb_lcfirst($text));

$text = "\t\t大声向宇宙呐喊 :) ...  ";
Assert::eq($text->mbTrim(), mb_trim($text));
Assert::eq($text->mbLTrim(), mb_ltrim($text));
Assert::eq($text->mbRTrim(), mb_rtrim($text));

$text = '大声大声大声向宇宙呐喊';
Assert::eq($text->mbSubstrCount('大声'), mb_substr_count($text, '大声'));

$text = "大声大声大声向宇宙呐喊";
Assert::eq($text->mbSubstr(0, -1), mb_substr($text, 0, -1));

$text = 'b大声大声大声向宇宙呐喊';
Assert::eq($text->mbUpper(), mb_strtoupper($text));

$text = 'BBBBBB大声大声大声向宇宙呐喊';
Assert::eq($text->mbLower(), mb_strtolower($text));

$email  = 'name我哦知道@example.com';
Assert::eq($email->mbFind('哦'), mb_strstr($email, '哦'));
Assert::eq($email->mbIFind('道'), mb_stristr($email, '道'));

$mystring1 = '当地特产';
$mystring2 = '现在只是谈谈';
Assert::true($mystring1->mbIndexOf('地') === mb_strpos($mystring1, '地'));
Assert::true($mystring2->mbIIndexOf('A') === mb_stripos($mystring2, 'a'));

$mystring = '啦啦啦啦啦啦啦';
Assert::true($mystring->mbLastIndexOf('好') === false);
Assert::true(mb_strrpos($mystring, '好') === false);
Assert::eq($mystring->mbILastIndexOf('啦'), mb_strripos($mystring, '啦'));
Assert::eq($mystring->mbLastCharIndexOf('啦'), mb_strrchr($mystring, '啦'));
Assert::eq($mystring->mbILastCharIndex('啦'), mb_strrichr($mystring, '啦'));

$text = '啦啦啦啦啦啦啦';
Assert::eq($text->mbLength(), mb_strlen($text));
Assert::eq($text->mbCut(0, 2), mb_strcut($text, 0, 2));
Assert::eq($text->mbDetectEncoding(), mb_detect_encoding($text));
Assert::eq($text->mbConvertEncoding('GBK'), mb_convert_encoding($text, 'GBK'));

$text = 'bbbbba啦啦啦啦啦啦啦';
Assert::eq(
    $text->mbConvertCase(MB_CASE_UPPER)->mbConvertCase(MB_CASE_LOWER),
    mb_convert_case(mb_convert_case($text, MB_CASE_UPPER), MB_CASE_LOWER)
    );
?>
--EXPECT--
