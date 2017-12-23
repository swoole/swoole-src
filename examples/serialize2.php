<?php
//only use in php7+

class myTestObject {
    public $test = "test";
    public $sub = "";
}

class mySubObject {
    public $sub = "sub";
    public $default = "";
}
$arr = new myTestObject();
$arr->sub = new mySubObject();
$arr->sub->default = new stdclass();
$obj = new \Swoole\Serialize();
$ser = $obj->pack($arr);


$ser2 = $obj->pack($arr,SWOOLE_FAST_PACK);

var_dump($obj->unpack($ser));
var_dump($obj->unpack($ser2));
var_dump($obj->unpack($ser, UNSERIALIZE_OBJECT_TO_STDCLASS));
var_dump($obj->unpack($ser2, UNSERIALIZE_OBJECT_TO_STDCLASS));
var_dump(UNSERIALIZE_OBJECT_TO_ARRAY);
var_dump(UNSERIALIZE_OBJECT_TO_STDCLASS);
var_dump(get_class($obj->unpack($ser, UNSERIALIZE_OBJECT_TO_STDCLASS)));

?>
