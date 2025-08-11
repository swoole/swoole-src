--TEST--
swoole_stdext/string_method: all string methods test
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$text = 'aaaaaa';
Assert::eq($text->length(), strlen($text));

$text = '';
Assert::eq($text->isEmpty(), true);

$text = 'A';
Assert::eq($text->lower(), strtolower($text));
Assert::eq($text->lowerFirst(), lcfirst($text));

$text = 'b';
Assert::eq($text->upper(), strtoupper($text));
Assert::eq($text->upperFirst(), ucfirst($text));

$text = 'hello world!';
Assert::eq($text->upperWords(), ucwords($text));

$text = "PHP isThirty\nYears Old!\tYay to the Elephant!\n";
$characters = "\0..\37!@\177..\377";
Assert::eq($text->addCSlashes($characters), addCSlashes($text, $characters));

$text = "O'Reilly?";
Assert::eq($text->addSlashes(), addslashes($text));

$text = 'This is quite a long string, which will get broken up because the line is going to be too long after base64 encoding it.';
Assert::eq($text->base64Encode()->chunkSplit(), chunk_split(base64_encode($text)));

$text = "Two Ts and one F.";
Assert::eq($text->countChars(1), count_chars($text, 1));

$text = "I'll \"walk\" the <b>dog</b> now";
Assert::eq($text->htmlEntityEncode()->htmlEntityDecode(), html_entity_decode(htmlentities($text)));

$text = "<a href='test'>Test</a>";
Assert::eq($text->htmlSpecialCharsEncode(ENT_QUOTES)->htmlSpecialCharsDecode(), htmlspecialchars_decode(htmlspecialchars($text, ENT_QUOTES)));

$text = "\t\tThese are a few words :) ...  ";
Assert::eq($text->trim(), trim($text));
Assert::eq($text->lTrim(), ltrim($text));
Assert::eq($text->rTrim(), rtrim($text));

$text = "first=value&arr[]=foo+bar&arr[]=baz";
parse_str($text, $result);
Assert::eq($text->parseStr(), $result);

$url = 'http://username:password@hostname:9090/path?arg=value#anchor';
Assert::eq($url->parseUrl(), parse_url($url));

$text = 'The lazy fox jumped over the fence';
Assert::eq($text->contains('lazy'), str_contains($text, 'lazy'));

if (PHP_VERSION_ID >= 80300) {
    $text = 'ABC';
    Assert::eq($text->incr(), str_increment($text));
    Assert::eq($text->decr(), str_decrement($text));
}

$text = "<body text=%BODY%>";
Assert::eq($text->replace("%BODY%", "black"), str_replace("%BODY%", "black", $text));
Assert::eq($text->iReplace("%body%", "black"), str_ireplace("%body%", "black", $text));

$text = "Alien";
Assert::eq($text->pad(10), str_pad($text, 10));

$text = "-=";
Assert::eq($text->repeat(10), str_repeat($text, 10));

$text = 'abcdef';
Assert::notEq($text->shuffle(), str_shuffle($text));

$text = "piece1 piece2 piece3 piece4 piece5 piece6";
Assert::eq($text->split(' '),  explode(' ', $text));

$text = 'The lazy fox jumped over the fence';
Assert::eq($text->startsWith('The'),  str_starts_with($text, 'The'));
Assert::eq($text->endsWith('fence'),  str_ends_with($text, 'fence'));

$text = "Hello fri3nd, you're
               looking          good today!";
Assert::eq($text->wordCount(0),  str_word_count($text, 0));
Assert::eq($text->wordCount(1),  str_word_count($text, 1));
Assert::eq($text->wordCount(2),  str_word_count($text, 2));

$var1 = "Hello";
$var2 = "hello";
Assert::eq($var1->iCompare($var2), strcasecmp($var1, $var2));
Assert::eq($var1->compare($var2), strcmp($var1, $var2));

$email  = 'name@example.com';
Assert::eq($email->find('@'), strstr($email, '@'));
Assert::eq($email->iFind('N'), stristr($email, 'N'));

$text = '<p>Test paragraph.</p><!-- Comment --> <a href="#fragment">Other text</a>';
Assert::eq($text->stripTags(), strip_tags($text));

$text = 'I\'d have a coffee.\nNot a problem.';
Assert::eq($text->stripCSlashes(), stripcslashes($text));

$str = "Is your name O\'reilly?";
Assert::eq($str->stripSlashes(), stripslashes($str));

$mystring1 = 'xyz';
$mystring2 = 'ABC';
Assert::true($mystring1->iIndexOf('A') === stripos($mystring1, 'a'));
Assert::true($mystring2->iIndexOf('A') === stripos($mystring2, 'a'));
Assert::eq($mystring2->indexOf('a'), strpos($mystring2, 'a'));

$mystring = 'Elephpant';
Assert::true($mystring->lastIndexOf('b') === false);
Assert::true(strrpos($mystring, 'b') === false);
Assert::eq($mystring->iLastIndexOf('E'), strripos($mystring, 'E'));
Assert::eq($mystring->lastCharIndexOf('E'), strrchr($mystring, 'E'));

$text = "abcdef";
Assert::eq($text->substr(0, -1), substr($text, 0, -1));
Assert::eq($text->substrCompare("bc", 1, 2), substr_compare($text, "bc", 1, 2));

$text = 'This is a test';
Assert::eq($text->substrCount('is'), substr_count($text, 'is'));

$var = 'ABCDEFGH:/MNRPQR/';
Assert::eq($var->substrReplace('bob', 0), substr_replace($var, 'bob', 0));

$var = 'abcdefghijklmn';
Assert::eq($var->reverse(), strrev($var));
Assert::eq($var->md5(), md5($var));
Assert::eq($var->sha1(), sha1($var));
Assert::eq($var->crc32(), crc32($var));
Assert::eq($var->hash('sha256'), hash('sha256', $var));

$str = 'This is an encoded string';
Assert::eq($str->base64Encode()->base64Decode(), base64_decode(base64_encode($str)));

$text = 'Data123!@-_ +';
Assert::eq($text->urlEncode()->urlDecode(), urldecode(urlencode($text)));

$text = 'foo @+%/';
Assert::eq($text->rawUrlEncode()->rawUrlDecode(), rawurldecode(rawurlencode($text)));

$pattern = "/php/i";
$text = "PHP is the web scripting language of choice.";
$result1 = $text->match("/php/i");
preg_match("/php/i", $text, $result2);
Assert::eq($result1, $result2);

$pattern = "/\(?  (\d{3})?  \)?  (?(1)  [\-\s] ) \d{3}-\d{4}/x";
$subject = "Call 555-1212 or 1-800-555-1212";
$result1 = $subject->matchAll($pattern);
preg_match_all($pattern, $subject, $result2);
Assert::eq($result1, $result2);

$text = '112';
Assert::eq($text->isNumeric(), is_numeric($text));
?>
--EXPECT--
