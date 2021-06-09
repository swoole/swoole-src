#include <ares.h>
#include <event.h>
#include <stdio.h>
#include <sys/socket.h>
#include <iostream>
#include <string>
#include <unordered_map>

std::string AddressToString(void *vaddr, int len) {
    auto addr = reinterpret_cast<unsigned char *>(vaddr);
    std::string addv;
    if (len == 4) {
        char buff[4 * 4 + 3 + 1];
        sprintf(buff, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
        return addv.assign(buff);
    } else if (len == 16) {
        for (int ii = 0; ii < 16; ii += 2) {
            if (ii > 0) addv.append(":");
            char buff[4 + 1];
            sprintf(buff, "%02x%02x", addr[ii], addr[ii + 1]);
            addv.append(buff);
        }
    }
    return addv;
}

struct context {
    struct event_base *base;
    struct event timeout_evt;
    ares_channel channel;
    ares_options ares_opts;
    std::unordered_map<int, struct event> events;
};

int main(int argc, char **argv) {
    context ctx = {};
    char lookups[] = "fb";
    int res;
    struct timeval tv, *tvp;

    if (argc < 2) {
        std::cout << "usage: " << argv[0] << "hostname" << std::endl;
        return -1;
    }

    ares_library_init(ARES_LIB_INIT_ALL);

    ctx.base = event_init();
    ctx.ares_opts.lookups = lookups;
    ctx.ares_opts.timeout = 3000;
    ctx.ares_opts.tries = 1;
    ctx.ares_opts.sock_state_cb_data = &ctx;
    ctx.ares_opts.sock_state_cb = [](void *arg, int fd, int readable, int writable) {
        auto ctx = reinterpret_cast<context *>(arg);
        short events = 0;
        auto &event = ctx->events[fd];
        if (readable) events |= EV_READ;
        if (writable) events |= EV_WRITE;

        printf("[sock_state_cb] fd=%d, events=%d\n", fd, events);

        if (events == 0) {
            event_del(&event);
            ctx->events.erase(fd);
            return;
        }

        if (event_assign(
                &event,
                ctx->base,
                fd,
                events,
                [](int fd, short events, void *arg) {
                    int w = ARES_SOCKET_BAD, r = ARES_SOCKET_BAD;
                    auto ctx = reinterpret_cast<context *>(arg);
                    if (events & EV_READ) r = fd;
                    if (events & EV_WRITE) w = fd;

                    printf("event callback, fd=%d, events=%d\n", fd, events);
                    ares_process_fd(ctx->channel, r, w);
                },
                ctx) != 0) {
            std::cout << "event_assign failed" << std::endl;
            return;
        }

        printf("add event, fd=%d, events=%d\n", fd, events);
        if (event_add(&event, nullptr) != 0) {
            std::cout << "event_add failed" << std::endl;
        }
    };

    if ((res = ares_init_options(&ctx.channel,
                                 &ctx.ares_opts,
                                 ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB | ARES_OPT_LOOKUPS)) !=
        ARES_SUCCESS) {
        std::cout << "ares feiled: " << ares_strerror(res) << std::endl;
        return res;
    }

    event_assign(
        &ctx.timeout_evt,
        ctx.base,
        -1,
        EV_TIMEOUT,
        [](int fd, short events, void *arg) {
            (void) fd;
            (void) events;
            auto ctx = reinterpret_cast<context *>(arg);
            printf("timeout callback, fd=%d, events=%d\n", fd, events);
            ares_process_fd(ctx->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        },
        &ctx);

    ares_gethostbyname(
        ctx.channel,
        argv[1],
        AF_INET,
        [](void *data, int status, int timeouts, struct hostent *hostent) {
            auto ctx = reinterpret_cast<context *>(data);

            printf("callback, timeout=%d, status=%d\n", timeouts, status);

            if (timeouts > 0) {
                std::cout << "loopkup timeout" << std::endl;
                return;
            } else {
                event_del(&ctx->timeout_evt);
            }

            if (status != ARES_SUCCESS) {
                std::cout << "lookup failed: " << ares_strerror(status) << std::endl;
                return;
            }

            if (hostent->h_addr_list) {
                char **paddr = hostent->h_addr_list;
                while (*paddr != nullptr) {
                    std::cout << "ip: " << AddressToString(*paddr, hostent->h_length) << std::endl;
                    paddr++;
                }
            }
        },
        &ctx);

    tvp = ares_timeout(ctx.channel, NULL, &tv);
    event_add(&ctx.timeout_evt, tvp);
    if ((res = event_base_loop(ctx.base, 0)) < 0) {
        std::cout << "event base loop failed: " << res << std::endl;
        return res;
    }
    printf("destroy begin\n");
    ares_destroy(ctx.channel);
    printf("destroy end\n");
    ares_library_cleanup();
    return 0;
}
