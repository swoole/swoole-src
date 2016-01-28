<?php
$an = new Swoole\Atomic(100);

$an->add(12);
echo $an->get()."\n";
