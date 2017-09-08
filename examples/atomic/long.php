<?php
$l = new Swoole\Atomic\Long( -2 ** 36);
echo $l->get()."\n";
echo $l->add(20)."\n";
echo $l->sub(20)."\n";
echo $l->sub(-20)."\n";
echo $l->cmpset(-2 ** 36, 0)."\n";
echo $l->cmpset(-2 ** 36 + 20, 0)."\n";