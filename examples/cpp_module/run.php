<?php
swoole_load_module(__DIR__.'/test.so');

function test()
{
    //var_dump(func_get_args());
    return array("hello world\n", "women", "tolx");
}

class Test2
{
    public $value = 1234;

    function __construct()
    {
      echo "class Test2 __construct\n";
      var_dump(func_get_args());
    }

    function hello()
    {
      echo __CLASS__.": ".__LINE__."\n";
    }
}

class Test
{
  public $name = "Test";
  //public $hello = "";

    function abc()
    {
      var_dump(func_get_args());
      var_dump($this->hello);
      return array("key" => 'rango', 'value' => 'tianfeng');
    }
}

function test2()
{
  var_dump(func_get_args());
  return new Test();
}


//$module = swoole_load_module(__DIR__.'/test.so');

/*
function php_hello_world($a, $b, $c, $d)
{
   $b = 1236 +  $b;
   return 3.1415926;
}
*/

$r = cpp_test(1234, 456, 789);
var_dump($r);

$options = array('');
$n = 100;


if (in_array('php', $options))
{
  /**
   * PHP用户函数
  */

  echo "=================PHP用户定义函数====================\n";
  $s = microtime(true);
  for($i =0; $i< $n; $i++)
  {
      //$ret = swoole_strerror(11);
      $ret = php_hello_world("abc", 1234, 459.55, "hello");
      //$ret = str_pad("i", 1, "p", STR_PAD_BOTH);
  }
  $use = (microtime(true) - $s);
  echo "use ".$use."s\n";
  echo "QPS=".number_format($n/$use)."\n";
  var_dump($ret);
}

if (in_array('cpp', $options))
{
  /**
   * C++扩展函数
   */
  echo "=================C++扩展函数====================\n";
  $s = microtime(true);
  for($i =0; $i< $n; $i++)
  {
      //$ret = swoole_strerror(11);
      $ret = cpp_hello_world("abc", 1234, 459.55, "hello");
      //$ret = str_pad("i", 1, "p", STR_PAD_BOTH);
  }
  $use = (microtime(true) - $s);
  echo "use ".$use."s\n";
  echo "QPS=".number_format($n/$use)."\n";
  var_dump($ret);
}

if (in_array('ext', $options))
{
  /**
   * PHP内置函数
   */
  echo "=================扩展函数====================\n";
  $s = microtime(true);
  for($i =0; $i< $n; $i++)
  {
      //$ret = swoole_strerror(11);
      $ret = swoole_version("abc", 1234, 459.55, "hello");
      //$ret = str_pad("i", 1, "p", STR_PAD_BOTH);
  }
  $use = (microtime(true) - $s);
  echo "use ".$use."s\n";
  echo "QPS=".number_format($n/$use)."\n";
  var_dump($ret);
  }
//sleep(1000);
