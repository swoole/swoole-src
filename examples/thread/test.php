<?php
$map = new Swoole\Thread\Map(2);
echo "1\n";
$map['uuid'] = uniqid();

echo "2\n";
$map['uuid'] = uniqid();

