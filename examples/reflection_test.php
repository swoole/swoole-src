<?php

$Ref_Swoole\Server = new ReflectionClass('Swoole\Server');
$methods = $Ref_Swoole\Server->getMethods();
foreach($methods as $method) {
    echo "----------------------------------------" .PHP_EOL;
    echo "method name : " . $method->name . PHP_EOL;
    echo "----------------------------------------" . PHP_EOL;
    $method = $Ref_Swoole\Server->getMethod($method->name);
    $params = $method->getParameters();
    print_r($params);
}
