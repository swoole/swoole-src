<?php
//only use in php7+

$arr = array(
    1111111111111
    
    );
$obj = new \Swoole\Serialize();
$ser = $obj->pack($arr);


$ser2 = $obj->pack($arr,SWOOLE_FAST_PACK);

var_dump($obj->unpack($ser));
var_dump($obj->unpack($ser2));

?>
