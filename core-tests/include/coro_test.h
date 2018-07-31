//
// Created by htf on 18-6-12.
//

#ifndef CORE_TESTS_COROUTINE_H
#define CORE_TESTS_COROUTINE_H

namespace swoole_test
{
    int coroutine_create_test1();
    void coroutine_socket_connect_refused();
    void coroutine_socket_connect_timeout();
    void coroutine_socket_connect_with_dns();
    void coroutine_socket_recv_fail();
    void coroutine_socket_recv_success();
    void coroutine_socket_bind_success();
    void coroutine_socket_bind_fail();
    void coroutine_socket_listen();
    void coroutine_socket_accept();
    int server_test( );
}

#endif //CORE_TESTS_COROUTINE_H
