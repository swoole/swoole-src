<?php
$s = scheduler();
$s->add(function (){
   Co::sleep(0.2);
   echo "hello world\n";
});
$s->start();