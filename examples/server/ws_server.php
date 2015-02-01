<?

$ser= new swoole_websocket_server("127.0.0.1", 9502);

$ser-> set(array( 
	"work_num" => 1
));

$ser-> on( 'open', function()
{
	echo "shakehand success\r\n";
});

$ser-> on( 'message', function( swoole_websocket_frame $frame)
{
	echo "receive {$frame->data}\r\n";
});

$ser-> on( 'close', function()
{
	echo "client closed\r\n";
});

?>
