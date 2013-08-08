定时器的使用
-----
swoole_server_addtimer($serv, 10);

第二个参数是定时器的间隔时间，单位为秒。swoole定时器的最小颗粒是1秒。支持多个定时器。注意不能存在2个相同间隔时间的定时器。
增加定时器后需要写一个回调函数

```php
swoole_server_handler($serv, 'onTimer', my_OnTimer);

function my_OnTimer($serv, $interval)
{
    echo "Timer[$interval] is call\n";
}

```
