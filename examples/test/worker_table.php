<?php
// #php  test.php table_num key_num
if($argc!=3)
{
	echo "wrong argv\r\n";
	exit();
}

$row=$argv[1];
$key_num=$argv[2];
$table=new swoole_table($row);
$table->column('name',swoole_table::TYPE_INT,4);
$table->column('count',swoole_table::TYPE_INT,4);
$table->create(); 

$process_num=20;
$fun='get_set';
for($i=0; $i<$process_num; $i++)
{
	if($fun=='get_set')
		$fun='set_get';
	else
		$fun='get_set';
	$worker=new swoole_process($fun,false,false);
	$worker->start();
}
/*
$worker=new swoole_process('get_set',false,false);//正向
$worker->start();
*/
//master process
while(true)
{
	for($i=$row-1; $i>=0; $i--)//逆向
	{
		$r=$table->set("id:{$i}",array("name"=>$i+1,"count"=>$i+2));
		$table->get('id:'.$i);
	}
	echo "master\r\n";
	sleep(5);
}

function set_get($worker)
{
	global $table;
	global $key_num;
	while(true)
	{
		for($i=$key_num-1;$i>=0;$i--)
		{
			$name=$i+1;
			$count=$i+2;
			$table->get('id:'.$i);
			$result=$table->set('id:'.$i,array('name'=>$name,'count'=>$count));
		}
		error_log("set_get\r\n",3,$worker->pid);
	}
}
function get_set($worker)
{
	global $table;
	global $key_num;
	while(true)
	{
		for($i=0;$i<$key_num;$i++)
		{
			$name=$i+1;
			$count=$i+2;
			$result=$table->set('id:'.$i,array('name'=>$name,'count'=>$count));
			$table->get('id:'.$i);
		}
		error_log("get_set\r\n",3,$worker->pid);
	}
}
