--TEST--
swoole_http_server: new cookie
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Cookie;
$cookie = new Cookie();
$cookie->withName('test')
    ->withValue('123456789')
    ->withExpires(time() + 3600)
    ->withPath('/path')
    ->withDomain('example.com')
    ->withSecure(true)
    ->withHttpOnly(true)
    ->withSameSite('None');

var_dump($cookie->toArray());
$cookie->reset();
var_dump($cookie->toArray());
?>
--EXPECTF--
array(11) {
  ["name"]=>
  string(4) "test"
  ["value"]=>
  string(9) "123456789"
  ["path"]=>
  string(5) "/path"
  ["domain"]=>
  string(11) "example.com"
  ["sameSite"]=>
  string(4) "None"
  ["priority"]=>
  string(0) ""
  ["encode"]=>
  bool(true)
  ["expires"]=>
  int(%d)
  ["secure"]=>
  bool(true)
  ["httpOnly"]=>
  bool(true)
  ["partitioned"]=>
  bool(false)
}
array(11) {
  ["name"]=>
  string(0) ""
  ["value"]=>
  string(0) ""
  ["path"]=>
  string(0) ""
  ["domain"]=>
  string(0) ""
  ["sameSite"]=>
  string(0) ""
  ["priority"]=>
  string(0) ""
  ["encode"]=>
  bool(true)
  ["expires"]=>
  int(0)
  ["secure"]=>
  bool(false)
  ["httpOnly"]=>
  bool(false)
  ["partitioned"]=>
  bool(false)
}
