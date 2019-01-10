--TEST--
swoole_serialize: Object test, extends protect
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set("display_errors", "Off");

abstract class AbstractAsyncTask
{
    protected $data = null;

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
object(test)#%d (1) {
  ["data":protected]=>
  string(3) "aaa"
}
string(3) "aaa"
