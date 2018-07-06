--TEST--
swoole_serialize: Object test, extends private
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!class_exists("swoole_serialize", false))
{
    echo "skip";
}
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

ini_set("display_errors", "Off");

abstract class AbstractAsyncTask
{
    private $data = null;

    public function __construct($data = null)
    {
        $this->data = $data;
    }

    public function getData()
    {
        return $this->data;
    }
}

class test extends AbstractAsyncTask
{

}


$data = swoole_serialize::pack(new test('aaa'));


$a = swoole_serialize::unpack($data);

var_dump($a);

var_dump($a->getData());

?>
--EXPECTF--
object(test)#1 (1) {
  ["data":"AbstractAsyncTask":private]=>
  string(3) "aaa"
}
string(3) "aaa"
