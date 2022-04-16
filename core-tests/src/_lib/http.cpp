#include "test_core.h"
#include "httplib_client.h"
#include "swoole_http.h"

namespace websocket = swoole::websocket;

namespace httplib {

bool Client::Upgrade(const char *_path, Headers &_headers) {
    set_keep_alive(true);
    _headers.emplace("Connection", "Upgrade");
    _headers.emplace("Upgrade", "websocket");
    _headers.emplace("Sec-Websocket-Key", "sN9cRrP/n9NdMgdcy2VJFQ==");
    _headers.emplace("Sec-WebSocket-Version", "13");

    auto resp = Get(_path, _headers);
    if (resp == nullptr or resp->status != SW_HTTP_SWITCHING_PROTOCOLS) {
        return false;
    }

    return true;
}

bool Client::Push(const char *data, size_t length, int opcode) {
    if (!socket_.is_open()) {
        return false;
    }
    return process_socket(socket_, [&](Stream &strm) {
        swString buffer = {};
        char buf[32];
        buffer.size = sizeof(buf);
        buffer.str = buf;

        websocket::encode(&buffer, data, length, opcode, websocket::FLAG_FIN | websocket::FLAG_ENCODE_HEADER_ONLY);
        strm.write(buffer.str, buffer.length);
        strm.write(data, length);
        return true;
    });
}

std::shared_ptr<WebSocketFrame> Client::Recv() {
    auto msg = std::make_shared<WebSocketFrame>();
    auto retval = process_socket(socket_, [&](Stream &strm) {
        swProtocol proto = {};
        proto.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        proto.get_package_length = websocket::get_package_length;
        proto.package_max_length = SW_INPUT_BUFFER_SIZE;

        char buf[1024];
        ssize_t packet_len;

        if (strm.read(buf, SW_WEBSOCKET_HEADER_LEN) <= 0) {
            return false;
        }
        swoole::PacketLength pl {
            buf,
            SW_WEBSOCKET_HEADER_LEN,
        };
        packet_len = proto.get_package_length(&proto, nullptr, &pl);
        if (packet_len < 0) {
            return false;
        }
        if (packet_len == 0) {
            if (strm.read(buf + SW_WEBSOCKET_HEADER_LEN, pl.header_len - SW_WEBSOCKET_HEADER_LEN) <= 0) {
                return false;
            }
            pl.buf_size = pl.header_len;
            packet_len = proto.get_package_length(&proto, nullptr, &pl);
            if (packet_len <= 0) {
                return false;
            }
        }

        char *data = (char *) malloc(packet_len + 1);
        if (data == nullptr) {
            return false;
        }
        data[packet_len] = 0;

        uint32_t header_len = pl.header_len > 0 ? pl.header_len : SW_WEBSOCKET_HEADER_LEN;
        memcpy(data, buf, header_len);

        ssize_t read_bytes = header_len;
        while (read_bytes < packet_len) {
            auto n_read = strm.read(data + read_bytes, packet_len - read_bytes);
            if (n_read <= 0) {
                free(data);
                return false;
            }
            read_bytes += n_read;
        }

        return websocket::decode(msg.get(), data, packet_len);
    });

    return retval ? msg : nullptr;
}

// HTTP client implementation
Client::Client(const std::string &host) : Client(host, 80, std::string(), std::string()) {}

Client::Client(const std::string &host, int port) : Client(host, port, std::string(), std::string()) {}

Client::Client(const std::string &host,
               int port,
               const std::string &client_cert_path,
               const std::string &client_key_path)
    : host_(host),
      port_(port),
      host_and_port_(host_ + ":" + std::to_string(port_)),
      client_cert_path_(client_cert_path),
      client_key_path_(client_key_path) {}

Client::~Client() {
    stop();
}

bool Client::is_valid() const {
    return true;
}

socket_t Client::create_client_socket() const {
    if (!proxy_host_.empty()) {
        return detail::create_client_socket(proxy_host_.c_str(),
                                            proxy_port_,
                                            tcp_nodelay_,
                                            socket_options_,
                                            connection_timeout_sec_,
                                            connection_timeout_usec_,
                                            interface_);
    }
    return detail::create_client_socket(host_.c_str(),
                                        port_,
                                        tcp_nodelay_,
                                        socket_options_,
                                        connection_timeout_sec_,
                                        connection_timeout_usec_,
                                        interface_);
}

bool Client::create_and_connect_socket(Socket &socket) {
    auto sock = create_client_socket();
    if (sock == INVALID_SOCKET) {
        return false;
    }
    socket.sock = sock;
    return true;
}

void Client::close_socket(Socket &socket, bool /*process_socket_ret*/) {
    detail::close_socket(socket.sock);
    socket_.sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    socket_.ssl = nullptr;
#endif
}

bool Client::read_response_line(Stream &strm, Response &res) {
    std::array<char, 2048> buf;

    detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

    if (!line_reader.getline()) {
        return false;
    }

    const static std::regex re("(HTTP/1\\.[01]) (\\d+?) .*\r\n");

    std::cmatch m;
    if (std::regex_match(line_reader.ptr(), m, re)) {
        res.version = std::string(m[1]);
        res.status = std::stoi(std::string(m[2]));
    }

    return true;
}

bool Client::send(const Request &req, Response &res) {
    std::lock_guard<std::recursive_mutex> request_mutex_guard(request_mutex_);

    {
        std::lock_guard<std::mutex> guard(socket_mutex_);

        auto is_alive = false;
        if (socket_.is_open()) {
            is_alive = detail::select_write(socket_.sock, 0, 0) > 0;
            if (!is_alive) {
                close_socket(socket_, false);
            }
        }

        if (!is_alive) {
            if (!create_and_connect_socket(socket_)) {
                return false;
            }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            // TODO: refactoring
            if (is_ssl()) {
                auto &scli = static_cast<SSLClient &>(*this);
                if (!proxy_host_.empty()) {
                    bool success = false;
                    if (!scli.connect_with_proxy(socket_, res, success)) {
                        return success;
                    }
                }

                if (!scli.initialize_ssl(socket_)) {
                    return false;
                }
            }
#endif
        }
    }

    auto close_connection = !keep_alive_;

    auto ret = process_socket(socket_, [&](Stream &strm) { return handle_request(strm, req, res, close_connection); });

    if (close_connection) {
        stop();
    }

    return ret;
}

bool Client::handle_request(Stream &strm, const Request &req, Response &res, bool close_connection) {
    if (req.path.empty()) {
        return false;
    }

    bool ret;

    if (!is_ssl() && !proxy_host_.empty()) {
        auto req2 = req;
        req2.path = "http://" + host_and_port_ + req.path;
        ret = process_request(strm, req2, res, close_connection);
    } else {
        ret = process_request(strm, req, res, close_connection);
    }

    if (!ret) {
        return false;
    }

    if (300 < res.status && res.status < 400 && follow_location_) {
        ret = redirect(req, res);
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if ((res.status == 401 || res.status == 407) && req.authorization_count_ < 5) {
        auto is_proxy = res.status == 407;
        const auto &username = is_proxy ? proxy_digest_auth_username_ : digest_auth_username_;
        const auto &password = is_proxy ? proxy_digest_auth_password_ : digest_auth_password_;

        if (!username.empty() && !password.empty()) {
            std::map<std::string, std::string> auth;
            if (parse_www_authenticate(res, auth, is_proxy)) {
                Request new_req = req;
                new_req.authorization_count_ += 1;
                auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
                new_req.headers.erase(key);
                new_req.headers.insert(make_digest_authentication_header(
                    req, auth, new_req.authorization_count_, random_string(10), username, password, is_proxy));

                Response new_res;

                ret = send(new_req, new_res);
                if (ret) {
                    res = new_res;
                }
            }
        }
    }
#endif

    return ret;
}

bool Client::redirect(const Request &req, Response &res) {
    if (req.redirect_count == 0) {
        return false;
    }

    auto location = res.get_header_value("location");
    if (location.empty()) {
        return false;
    }

    const static std::regex re(R"(^(?:(https?):)?(?://([^:/?#]*)(?::(\d+))?)?([^?#]*(?:\?[^#]*)?)(?:#.*)?)");

    std::smatch m;
    if (!std::regex_match(location, m, re)) {
        return false;
    }

    auto scheme = is_ssl() ? "https" : "http";

    auto next_scheme = m[1].str();
    auto next_host = m[2].str();
    auto port_str = m[3].str();
    auto next_path = m[4].str();

    auto next_port = port_;
    if (!port_str.empty()) {
        next_port = std::stoi(port_str);
    } else if (!next_scheme.empty()) {
        next_port = next_scheme == "https" ? 443 : 80;
    }

    if (next_scheme.empty()) {
        next_scheme = scheme;
    }
    if (next_host.empty()) {
        next_host = host_;
    }
    if (next_path.empty()) {
        next_path = "/";
    }

    if (next_scheme == scheme && next_host == host_ && next_port == port_) {
        return detail::redirect(*this, req, res, next_path);
    } else {
        if (next_scheme == "https") {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            SSLClient cli(next_host.c_str(), next_port);
            cli.copy_settings(*this);
            return detail::redirect(cli, req, res, next_path);
#else
            return false;
#endif
        } else {
            Client cli(next_host.c_str(), next_port);
            cli.copy_settings(*this);
            return detail::redirect(cli, req, res, next_path);
        }
    }
}

bool Client::write_request(Stream &strm, const Request &req, bool close_connection) {
    detail::BufferStream bstrm;

    // Request line
    const auto &path = detail::encode_url(req.path);

    bstrm.write_format("%s %s HTTP/1.1\r\n", req.method.c_str(), path.c_str());

    // Additonal headers
    Headers headers;
    if (close_connection) {
        headers.emplace("Connection", "close");
    }

    if (!req.has_header("Host")) {
        if (is_ssl()) {
            if (port_ == 443) {
                headers.emplace("Host", host_);
            } else {
                headers.emplace("Host", host_and_port_);
            }
        } else {
            if (port_ == 80) {
                headers.emplace("Host", host_);
            } else {
                headers.emplace("Host", host_and_port_);
            }
        }
    }

    if (!req.has_header("Accept")) {
        headers.emplace("Accept", "*/*");
    }

    if (!req.has_header("User-Agent")) {
        headers.emplace("User-Agent", USER_AGENT);
    }

    if (req.body.empty()) {
        if (req.content_provider) {
            auto length = std::to_string(req.content_length);
            headers.emplace("Content-Length", length);
        } else {
            headers.emplace("Content-Length", "0");
        }
    } else {
        if (!req.has_header("Content-Type")) {
            headers.emplace("Content-Type", "text/plain");
        }

        if (!req.has_header("Content-Length")) {
            auto length = std::to_string(req.body.size());
            headers.emplace("Content-Length", length);
        }
    }

    if (!basic_auth_username_.empty() && !basic_auth_password_.empty()) {
        headers.insert(make_basic_authentication_header(basic_auth_username_, basic_auth_password_, false));
    }

    if (!proxy_basic_auth_username_.empty() && !proxy_basic_auth_password_.empty()) {
        headers.insert(make_basic_authentication_header(proxy_basic_auth_username_, proxy_basic_auth_password_, true));
    }

    detail::write_headers(bstrm, req, headers);

    // Flush buffer
    auto &data = bstrm.get_buffer();
    if (!detail::write_data(strm, data.data(), data.size())) {
        return false;
    }

    // Body
    if (req.body.empty()) {
        if (req.content_provider) {
            size_t offset = 0;
            size_t end_offset = req.content_length;

            bool ok = true;

            DataSink data_sink;
            data_sink.write = [&](const char *d, size_t l) {
                if (ok) {
                    if (detail::write_data(strm, d, l)) {
                        offset += l;
                    } else {
                        ok = false;
                    }
                }
            };
            data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

            while (offset < end_offset) {
                if (!req.content_provider(offset, end_offset - offset, data_sink)) {
                    return false;
                }
                if (!ok) {
                    return false;
                }
            }
        }
    } else {
        return detail::write_data(strm, req.body.data(), req.body.size());
    }

    return true;
}

std::shared_ptr<Response> Client::send_with_content_provider(const char *method,
                                                             const char *path,
                                                             const Headers &headers,
                                                             const std::string &body,
                                                             size_t content_length,
                                                             ContentProvider content_provider,
                                                             const char *content_type) {
    Request req;
    req.method = method;
    req.headers = headers;
    req.path = path;

    if (content_type) {
        req.headers.emplace("Content-Type", content_type);
    }

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
    if (compress_) {
        if (content_provider) {
            size_t offset = 0;

            DataSink data_sink;
            data_sink.write = [&](const char *data, size_t data_len) {
                req.body.append(data, data_len);
                offset += data_len;
            };
            data_sink.is_writable = [&](void) { return true; };

            while (offset < content_length) {
                if (!content_provider(offset, content_length - offset, data_sink)) {
                    return nullptr;
                }
            }
        } else {
            req.body = body;
        }

        if (!detail::compress(req.body)) {
            return nullptr;
        }
        req.headers.emplace("Content-Encoding", "gzip");
    } else
#endif
    {
        if (content_provider) {
            req.content_length = content_length;
            req.content_provider = content_provider;
        } else {
            req.body = body;
        }
    }

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

bool Client::process_request(Stream &strm, const Request &req, Response &res, bool close_connection) {
    // Send request
    if (!write_request(strm, req, close_connection)) {
        return false;
    }

    // Receive response and headers
    if (!read_response_line(strm, res) || !detail::read_headers(strm, res.headers)) {
        return false;
    }

    if (req.response_handler) {
        if (!req.response_handler(res)) {
            return false;
        }
    }

    // Body
    if (req.method != "HEAD" && req.method != "CONNECT") {
        auto out =
            req.content_receiver
                ? static_cast<ContentReceiver>([&](const char *buf, size_t n) { return req.content_receiver(buf, n); })
                : static_cast<ContentReceiver>([&](const char *buf, size_t n) {
                      if (res.body.size() + n > res.body.max_size()) {
                          return false;
                      }
                      res.body.append(buf, n);
                      return true;
                  });

        int dummy_status;
        if (!detail::read_content(
                strm, res, (std::numeric_limits<size_t>::max)(), dummy_status, req.progress, out, decompress_)) {
            return false;
        }
    }

    if (res.get_header_value("Connection") == "close" || res.version == "HTTP/1.0") {
        stop();
    }

    // Log
    if (logger_) {
        logger_(req, res);
    }

    return true;
}

bool Client::process_socket(Socket &socket, std::function<bool(Stream &strm)> callback) {
    return detail::process_client_socket(
        socket.sock, read_timeout_sec_, read_timeout_usec_, write_timeout_sec_, write_timeout_usec_, callback);
}

bool Client::is_ssl() const {
    return false;
}

std::shared_ptr<Response> Client::Get(const char *path) {
    return Get(path, Headers(), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path, Progress progress) {
    return Get(path, Headers(), std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path, const Headers &headers) {
    return Get(path, headers, Progress());
}

std::shared_ptr<Response> Client::Get(const char *path, const Headers &headers, Progress progress) {
    Request req;
    req.method = "GET";
    req.path = path;
    req.headers = headers;
    req.progress = std::move(progress);

    auto res = std::make_shared<Response>();
    return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Get(const char *path, ContentReceiver content_receiver) {
    return Get(path, Headers(), nullptr, std::move(content_receiver), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path, ContentReceiver content_receiver, Progress progress) {
    return Get(path, Headers(), nullptr, std::move(content_receiver), std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path, const Headers &headers, ContentReceiver content_receiver) {
    return Get(path, headers, nullptr, std::move(content_receiver), Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
                                      const Headers &headers,
                                      ContentReceiver content_receiver,
                                      Progress progress) {
    return Get(path, headers, nullptr, std::move(content_receiver), std::move(progress));
}

std::shared_ptr<Response> Client::Get(const char *path,
                                      const Headers &headers,
                                      ResponseHandler response_handler,
                                      ContentReceiver content_receiver) {
    return Get(path, headers, std::move(response_handler), content_receiver, Progress());
}

std::shared_ptr<Response> Client::Get(const char *path,
                                      const Headers &headers,
                                      ResponseHandler response_handler,
                                      ContentReceiver content_receiver,
                                      Progress progress) {
    Request req;
    req.method = "GET";
    req.path = path;
    req.headers = headers;
    req.response_handler = std::move(response_handler);
    req.content_receiver = std::move(content_receiver);
    req.progress = std::move(progress);

    auto res = std::make_shared<Response>();
    return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Head(const char *path) {
    return Head(path, Headers());
}

std::shared_ptr<Response> Client::Head(const char *path, const Headers &headers) {
    Request req;
    req.method = "HEAD";
    req.headers = headers;
    req.path = path;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Post(const char *path) {
    return Post(path, std::string(), nullptr);
}

std::shared_ptr<Response> Client::Post(const char *path, const std::string &body, const char *content_type) {
    return Post(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Post(const char *path,
                                       const Headers &headers,
                                       const std::string &body,
                                       const char *content_type) {
    return send_with_content_provider("POST", path, headers, body, 0, nullptr, content_type);
}

std::shared_ptr<Response> Client::Post(const char *path, const Params &params) {
    return Post(path, Headers(), params);
}

std::shared_ptr<Response> Client::Post(const char *path,
                                       size_t content_length,
                                       ContentProvider content_provider,
                                       const char *content_type) {
    return Post(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Post(const char *path,
                                       const Headers &headers,
                                       size_t content_length,
                                       ContentProvider content_provider,
                                       const char *content_type) {
    return send_with_content_provider(
        "POST", path, headers, std::string(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Post(const char *path, const Headers &headers, const Params &params) {
    auto query = detail::params_to_query_str(params);
    return Post(path, headers, query, "application/x-www-form-urlencoded");
}

std::shared_ptr<Response> Client::Post(const char *path, const MultipartFormDataItems &items) {
    return Post(path, Headers(), items);
}

std::shared_ptr<Response> Client::Post(const char *path, const Headers &headers, const MultipartFormDataItems &items) {
    auto boundary = detail::make_multipart_data_boundary();

    std::string body;

    for (const auto &item : items) {
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"" + item.name + "\"";
        if (!item.filename.empty()) {
            body += "; filename=\"" + item.filename + "\"";
        }
        body += "\r\n";
        if (!item.content_type.empty()) {
            body += "Content-Type: " + item.content_type + "\r\n";
        }
        body += "\r\n";
        body += item.content + "\r\n";
    }

    body += "--" + boundary + "--\r\n";

    std::string content_type = "multipart/form-data; boundary=" + boundary;
    return Post(path, headers, body, content_type.c_str());
}

std::shared_ptr<Response> Client::Put(const char *path) {
    return Put(path, std::string(), nullptr);
}

std::shared_ptr<Response> Client::Put(const char *path, const std::string &body, const char *content_type) {
    return Put(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
                                      const Headers &headers,
                                      const std::string &body,
                                      const char *content_type) {
    return send_with_content_provider("PUT", path, headers, body, 0, nullptr, content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
                                      size_t content_length,
                                      ContentProvider content_provider,
                                      const char *content_type) {
    return Put(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Put(const char *path,
                                      const Headers &headers,
                                      size_t content_length,
                                      ContentProvider content_provider,
                                      const char *content_type) {
    return send_with_content_provider(
        "PUT", path, headers, std::string(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Put(const char *path, const Params &params) {
    return Put(path, Headers(), params);
}

std::shared_ptr<Response> Client::Put(const char *path, const Headers &headers, const Params &params) {
    auto query = detail::params_to_query_str(params);
    return Put(path, headers, query, "application/x-www-form-urlencoded");
}

std::shared_ptr<Response> Client::Patch(const char *path, const std::string &body, const char *content_type) {
    return Patch(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Patch(const char *path,
                                        const Headers &headers,
                                        const std::string &body,
                                        const char *content_type) {
    return send_with_content_provider("PATCH", path, headers, body, 0, nullptr, content_type);
}

std::shared_ptr<Response> Client::Patch(const char *path,
                                        size_t content_length,
                                        ContentProvider content_provider,
                                        const char *content_type) {
    return Patch(path, Headers(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Patch(const char *path,
                                        const Headers &headers,
                                        size_t content_length,
                                        ContentProvider content_provider,
                                        const char *content_type) {
    return send_with_content_provider(
        "PATCH", path, headers, std::string(), content_length, content_provider, content_type);
}

std::shared_ptr<Response> Client::Delete(const char *path) {
    return Delete(path, Headers(), std::string(), nullptr);
}

std::shared_ptr<Response> Client::Delete(const char *path, const std::string &body, const char *content_type) {
    return Delete(path, Headers(), body, content_type);
}

std::shared_ptr<Response> Client::Delete(const char *path, const Headers &headers) {
    return Delete(path, headers, std::string(), nullptr);
}

std::shared_ptr<Response> Client::Delete(const char *path,
                                         const Headers &headers,
                                         const std::string &body,
                                         const char *content_type) {
    Request req;
    req.method = "DELETE";
    req.headers = headers;
    req.path = path;

    if (content_type) {
        req.headers.emplace("Content-Type", content_type);
    }
    req.body = body;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

std::shared_ptr<Response> Client::Options(const char *path) {
    return Options(path, Headers());
}

std::shared_ptr<Response> Client::Options(const char *path, const Headers &headers) {
    Request req;
    req.method = "OPTIONS";
    req.path = path;
    req.headers = headers;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

size_t Client::is_socket_open() const {
    std::lock_guard<std::mutex> guard(socket_mutex_);
    return socket_.is_open();
}

void Client::stop() {
    std::lock_guard<std::mutex> guard(socket_mutex_);
    if (socket_.is_open()) {
        detail::shutdown_socket(socket_.sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        close_socket(socket_, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void Client::set_timeout_sec(time_t timeout_sec) {
    set_connection_timeout(timeout_sec, 0);
}

void Client::set_connection_timeout(time_t sec, time_t usec) {
    connection_timeout_sec_ = sec;
    connection_timeout_usec_ = usec;
}

void Client::set_read_timeout(time_t sec, time_t usec) {
    read_timeout_sec_ = sec;
    read_timeout_usec_ = usec;
}

void Client::set_write_timeout(time_t sec, time_t usec) {
    write_timeout_sec_ = sec;
    write_timeout_usec_ = usec;
}

void Client::set_basic_auth(const char *username, const char *password) {
    basic_auth_username_ = username;
    basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
void Client::set_digest_auth(const char *username, const char *password) {
    digest_auth_username_ = username;
    digest_auth_password_ = password;
}
#endif

void Client::set_keep_alive(bool on) {
    keep_alive_ = on;
}

void Client::set_follow_location(bool on) {
    follow_location_ = on;
}

void Client::set_tcp_nodelay(bool on) {
    tcp_nodelay_ = on;
}

void Client::set_socket_options(SocketOptions socket_options) {
    socket_options_ = socket_options;
}

void Client::set_compress(bool on) {
    compress_ = on;
}

void Client::set_decompress(bool on) {
    decompress_ = on;
}

void Client::set_interface(const char *intf) {
    interface_ = intf;
}

void Client::set_proxy(const char *host, int port) {
    proxy_host_ = host;
    proxy_port_ = port;
}

void Client::set_proxy_basic_auth(const char *username, const char *password) {
    proxy_basic_auth_username_ = username;
    proxy_basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
void Client::set_proxy_digest_auth(const char *username, const char *password) {
    proxy_digest_auth_username_ = username;
    proxy_digest_auth_password_ = password;
}
#endif

void Client::set_logger(Logger logger) {
    logger_ = std::move(logger);
}

}  // namespace httplib
