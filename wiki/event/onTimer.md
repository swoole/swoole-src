onTimer
---
定时器触发，函数原型为
```php
void onTimer(resource $server, int $interval);
```
$interval是定时器时间间隔，根据$interval的值来区分是哪个定时器触发的。

> onTimer在主进程内被调用
