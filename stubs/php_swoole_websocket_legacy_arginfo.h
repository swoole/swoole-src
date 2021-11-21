ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_push, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_disconnect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, code)
    ZEND_ARG_INFO(0, reason)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_pack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_unpack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_isEstablished, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_frame_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_swoole_websocket_frame___toString, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Swoole_WebSocket_Server_push          arginfo_swoole_websocket_server_push
#define arginfo_class_Swoole_WebSocket_Server_disconnect    arginfo_swoole_websocket_server_disconnect
#define arginfo_class_Swoole_WebSocket_Server_isEstablished arginfo_swoole_websocket_server_isEstablished
#define arginfo_class_Swoole_WebSocket_Server_pack          arginfo_swoole_websocket_server_pack
#define arginfo_class_Swoole_WebSocket_Server_unpack        arginfo_swoole_websocket_server_unpack
#define arginfo_class_Swoole_WebSocket_Frame___toString     arginfo_swoole_websocket_frame___toString
#define arginfo_class_Swoole_WebSocket_Frame_pack           arginfo_swoole_websocket_server_pack
#define arginfo_class_Swoole_WebSocket_Frame_unpack         arginfo_swoole_websocket_server_unpack
