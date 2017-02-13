<?php
//only use in php7+

$arr = array(
    1111111111111
    
    );
$obj = new \Swoole\Serialize();
$ser = $obj->pack($arr);



var_dump($obj->unpack($ser));

?>
