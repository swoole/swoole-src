/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 01414ef8c57f19835add339963d424fb625701f3 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_WebSocket_Server_push, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, opcode, IS_LONG, 0, "WEBSOCKET_OPCODE_TEXT")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "SWOOLE_WEBSOCKET_FLAG_FIN")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_WebSocket_Server_isEstablished, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_WebSocket_Server_pack, 0, 1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, opcode, IS_LONG, 0, "WEBSOCKET_OPCODE_TEXT")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "SWOOLE_WEBSOCKET_FLAG_FIN")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_class_Swoole_WebSocket_Server_unpack, 0, 1, Swoole\\WebSocket\\Frame, MAY_BE_BOOL)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_WebSocket_Server_pack arginfo_class_Swoole_WebSocket_Server_pack

#define arginfo_class_Swoole_WebSocket_Server_unpack arginfo_class_Swoole_WebSocket_Server_unpack

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_WebSocket_Server_disconnect, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, fd, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, code, IS_LONG, 0, "SWOOLE_WEBSOCKET_CLOSE_NORMAL")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reason, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Swoole_WebSocket_Frame___toString, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_WebSocket_Frame_pack arginfo_class_Swoole_WebSocket_Server_pack

#define arginfo_class_Swoole_WebSocket_Frame_unpack arginfo_class_Swoole_WebSocket_Server_unpack

#define arginfo_class_Swoole_WebSocket_Frame_pack arginfo_class_Swoole_WebSocket_Server_pack

#define arginfo_class_Swoole_WebSocket_Frame_unpack arginfo_class_Swoole_WebSocket_Server_unpack
