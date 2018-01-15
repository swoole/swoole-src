<?php
use Swoole\Coroutine\Channel as chan;
use Swoole\Coroutine as co;

$c1 = new chan(10);
$c2 = new chan(10);
$c3 = new chan(10);

co::create(function () {
  $data = rand(1000, 9999);
  for ($i= 0; $i < 3; $i++) {
    $result = chan::select([
        [$c1, chan::POP],
        [$c2, chan::POP],
        [$c3, chan::PUSH, $data],
      ], 0.5);
    //超时
    $result = false;
    //返回3个结果，3个操作全部完成
    //返回2个结果，无协程调度
    //无可用IO，yield，等待其中一个IO返回
  }
});
