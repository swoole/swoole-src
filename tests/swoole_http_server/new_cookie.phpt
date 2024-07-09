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
$cookie->setName('test');
$cookie->setValue('123456789');
$cookie->setExpires(time() + 3600);
$cookie->setPath('/');
$cookie->setDomain('example.com');
$cookie->setSecure(true);
$cookie->setHttpOnly(true);
$cookie->setSameSite('None');
var_dump($cookie->getCookie());
$cookie->reset();
var_dump($cookie->getCookie());
?>
--EXPECTF--
array(9) {
  ["name"]=>
  string(4) "test"
  ["value"]=>
  string(9) "123456789"
  ["domain"]=>
  string(1) "/"
  ["sameSite"]=>
  string(4) "test"
  ["priority"]=>
  string(0) ""
  ["expires"]=>
  int(%d)
  ["secure"]=>
  bool(true)
  ["httpOnly"]=>
  bool(true)
  ["partitioned"]=>
  bool(false)
}
array(9) {
  ["name"]=>
  string(0) ""
  ["value"]=>
  string(0) ""
  ["domain"]=>
  string(0) ""
  ["sameSite"]=>
  string(0) ""
  ["priority"]=>
  string(0) ""
  ["expires"]=>
  int(0)
  ["secure"]=>
  bool(false)
  ["httpOnly"]=>
  bool(false)
  ["partitioned"]=>
  bool(false)
}
