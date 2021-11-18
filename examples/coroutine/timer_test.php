<?
/**
 * @Author: winterswang
 * @Date:   2016-06-26 16:34:02
 * @Last Modified by:   winterswang
 * @Last Modified time: 2016-06-26 16:41:46
 */

Swoole\Timer::after(1000, function(){
    echo " timer after timeout\n";
});

Swoole\Timer::tick(1000, function(){
    echo "timer tick timeout\n";
});
?>
