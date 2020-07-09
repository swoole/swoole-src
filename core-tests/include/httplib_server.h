/**
 * httplib.h
 *
 * Copyright (c) 2020 Yuji Hirose. All rights reserved.
 * MIT License
 * GitHub: https://github.com/yhirose/cpp-httplib
*/

#pragma once

#include "coroutine_system.h"
#include "coroutine_socket.h"
#include "httplib_client.h"

using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::Coroutine;

namespace httplib {

class ContentReader {
public:
  using Reader = std::function<bool(ContentReceiver receiver)>;
  using MultipartReader = std::function<bool(MultipartContentHeader header,
                                             ContentReceiver receiver)>;

  ContentReader(Reader reader, MultipartReader multipart_reader)
      : reader_(reader), multipart_reader_(multipart_reader) {}

  bool operator()(MultipartContentHeader header,
                  ContentReceiver receiver) const {
    return multipart_reader_(header, receiver);
  }

  bool operator()(ContentReceiver receiver) const { return reader_(receiver); }

  Reader reader_;
  MultipartReader multipart_reader_;
};

class Server {
public:
  using Handler = std::function<void(const Request &, Response &)>;
  using HandlerWithContentReader = std::function<void(
      const Request &, Response &, const ContentReader &content_reader)>;
  using Expect100ContinueHandler =
      std::function<int(const Request &, Response &)>;

  Server();

  virtual ~Server();

  virtual bool is_valid() const;

  Server &Get(const char *pattern, Handler handler);
  Server &Post(const char *pattern, Handler handler);
  Server &Post(const char *pattern, HandlerWithContentReader handler);
  Server &Put(const char *pattern, Handler handler);
  Server &Put(const char *pattern, HandlerWithContentReader handler);
  Server &Patch(const char *pattern, Handler handler);
  Server &Patch(const char *pattern, HandlerWithContentReader handler);
  Server &Delete(const char *pattern, Handler handler);
  Server &Delete(const char *pattern, HandlerWithContentReader handler);
  Server &Options(const char *pattern, Handler handler);

  CPPHTTPLIB_DEPRECATED bool set_base_dir(const char *dir,
                                          const char *mount_point = nullptr);
  bool set_mount_point(const char *mount_point, const char *dir);
  bool remove_mount_point(const char *mount_point);
  void set_file_extension_and_mimetype_mapping(const char *ext,
                                               const char *mime);
  void set_file_request_handler(Handler handler);

  void set_error_handler(Handler handler);
  void set_expect_100_continue_handler(Expect100ContinueHandler handler);
  void set_logger(Logger logger);

  void set_tcp_nodelay(bool on);
  void set_socket_options(SocketOptions socket_options);

  void set_keep_alive_max_count(size_t count);
  void set_read_timeout(time_t sec, time_t usec = 0);
  void set_write_timeout(time_t sec, time_t usec = 0);
  void set_idle_interval(time_t sec, time_t usec = 0);

  void set_payload_max_length(size_t length);

  bool bind_to_port(const char *host, int port, int socket_flags = 0);
  int bind_to_any_port(const char *host, int socket_flags = 0);
  bool listen_after_bind();

  bool listen(const char *host, int port, int socket_flags = 0);

  bool is_running() const;
  void stop();

protected:
  bool process_request(Stream &strm, bool close_connection,
                       bool &connection_closed,
                       const std::function<void(Request &)> &setup_request);

  Socket *svr_sock_;
  size_t keep_alive_max_count_ = CPPHTTPLIB_KEEPALIVE_MAX_COUNT;
  time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;
  time_t idle_interval_sec_ = CPPHTTPLIB_IDLE_INTERVAL_SECOND;
  time_t idle_interval_usec_ = CPPHTTPLIB_IDLE_INTERVAL_USECOND;
  size_t payload_max_length_ = CPPHTTPLIB_PAYLOAD_MAX_LENGTH;

private:
  using Handlers = std::vector<std::pair<std::regex, Handler>>;
  using HandlersForContentReader =
      std::vector<std::pair<std::regex, HandlerWithContentReader>>;

  Socket *create_server_socket(const char *host, int port, int socket_flags,
                                SocketOptions socket_options) const;
  int bind_internal(const char *host, int port, int socket_flags);
  bool listen_internal();

  bool routing(Request &req, Response &res, Stream &strm);
  bool handle_file_request(Request &req, Response &res, bool head = false);
  bool dispatch_request(Request &req, Response &res, Handlers &handlers);
  bool dispatch_request_for_content_reader(Request &req, Response &res,
                                           ContentReader content_reader,
                                           HandlersForContentReader &handlers);

  bool parse_request_line(const char *s, Request &req);
  bool write_response(Stream &strm, bool close_connection, const Request &req,
                      Response &res);
  bool write_content_with_provider(Stream &strm, const Request &req,
                                   Response &res, const std::string &boundary,
                                   const std::string &content_type);
  bool read_content(Stream &strm, Request &req, Response &res);
  bool
  read_content_with_content_receiver(Stream &strm, Request &req, Response &res,
                                     ContentReceiver receiver,
                                     MultipartContentHeader multipart_header,
                                     ContentReceiver multipart_receiver);
  bool read_content_core(Stream &strm, Request &req, Response &res,
                         ContentReceiver receiver,
                         MultipartContentHeader mulitpart_header,
                         ContentReceiver multipart_receiver);

  virtual bool process_and_close_socket(Socket *sock);

  std::atomic<bool> is_running_;
  std::vector<std::pair<std::string, std::string>> base_dirs_;
  std::map<std::string, std::string> file_extension_and_mimetype_map_;
  Handler file_request_handler_;
  Handlers get_handlers_;
  Handlers post_handlers_;
  HandlersForContentReader post_handlers_for_content_reader_;
  Handlers put_handlers_;
  HandlersForContentReader put_handlers_for_content_reader_;
  Handlers patch_handlers_;
  HandlersForContentReader patch_handlers_for_content_reader_;
  Handlers delete_handlers_;
  HandlersForContentReader delete_handlers_for_content_reader_;
  Handlers options_handlers_;
  Handler error_handler_;
  Logger logger_;
  Expect100ContinueHandler expect_100_continue_handler_;

  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  SocketOptions socket_options_ = default_socket_options;
};

// HTTP server implementation
inline Server::Server() : svr_sock_(nullptr), is_running_(false) {
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif
}

inline Server::~Server() {
    if (svr_sock_) {
        delete svr_sock_;
    }
}

inline Server &Server::Get(const char *pattern, Handler handler) {
  get_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Post(const char *pattern, Handler handler) {
  post_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Post(const char *pattern,
                            HandlerWithContentReader handler) {
  post_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Put(const char *pattern, Handler handler) {
  put_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Put(const char *pattern,
                           HandlerWithContentReader handler) {
  put_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Patch(const char *pattern, Handler handler) {
  patch_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Patch(const char *pattern,
                             HandlerWithContentReader handler) {
  patch_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Delete(const char *pattern, Handler handler) {
  delete_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Delete(const char *pattern,
                              HandlerWithContentReader handler) {
  delete_handlers_for_content_reader_.push_back(
      std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline Server &Server::Options(const char *pattern, Handler handler) {
  options_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
  return *this;
}

inline bool Server::set_base_dir(const char *dir, const char *mount_point) {
  return set_mount_point(mount_point, dir);
}

inline bool Server::set_mount_point(const char *mount_point, const char *dir) {
  if (detail::is_dir(dir)) {
    std::string mnt = mount_point ? mount_point : "/";
    if (!mnt.empty() && mnt[0] == '/') {
      base_dirs_.emplace_back(mnt, dir);
      return true;
    }
  }
  return false;
}

inline bool Server::remove_mount_point(const char *mount_point) {
  for (auto it = base_dirs_.begin(); it != base_dirs_.end(); ++it) {
    if (it->first == mount_point) {
      base_dirs_.erase(it);
      return true;
    }
  }
  return false;
}

inline void Server::set_file_extension_and_mimetype_mapping(const char *ext,
                                                            const char *mime) {
  file_extension_and_mimetype_map_[ext] = mime;
}

inline void Server::set_file_request_handler(Handler handler) {
  file_request_handler_ = std::move(handler);
}

inline void Server::set_error_handler(Handler handler) {
  error_handler_ = std::move(handler);
}

inline void Server::set_tcp_nodelay(bool on) { tcp_nodelay_ = on; }

inline void Server::set_socket_options(SocketOptions socket_options) {
  socket_options_ = socket_options;
}

inline void Server::set_logger(Logger logger) { logger_ = std::move(logger); }

inline void
Server::set_expect_100_continue_handler(Expect100ContinueHandler handler) {
  expect_100_continue_handler_ = std::move(handler);
}

inline void Server::set_keep_alive_max_count(size_t count) {
  keep_alive_max_count_ = count;
}

inline void Server::set_read_timeout(time_t sec, time_t usec) {
  read_timeout_sec_ = sec;
  read_timeout_usec_ = usec;
}

inline void Server::set_write_timeout(time_t sec, time_t usec) {
  write_timeout_sec_ = sec;
  write_timeout_usec_ = usec;
}

inline void Server::set_idle_interval(time_t sec, time_t usec) {
  idle_interval_sec_ = sec;
  idle_interval_usec_ = usec;
}

inline void Server::set_payload_max_length(size_t length) {
  payload_max_length_ = length;
}

inline bool Server::bind_to_port(const char *host, int port, int socket_flags) {
  if (bind_internal(host, port, socket_flags) < 0) return false;
  return true;
}
inline int Server::bind_to_any_port(const char *host, int socket_flags) {
  return bind_internal(host, 0, socket_flags);
}

inline bool Server::listen_after_bind() { return listen_internal(); }

inline bool Server::listen(const char *host, int port, int socket_flags) {
  return bind_to_port(host, port, socket_flags) && listen_internal();
}

inline bool Server::is_running() const { return is_running_; }

inline void Server::stop() {
    if (is_running_) {
        is_running_ = false;
        svr_sock_->cancel(SW_EVENT_READ);
    }
}

inline bool Server::parse_request_line(const char *s, Request &req) {
  const static std::regex re(
      "(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PRI) "
      "(([^?]+)(?:\\?(.*?))?) (HTTP/1\\.[01])\r\n");

  std::cmatch m;
  if (std::regex_match(s, m, re)) {
    req.version = std::string(m[5]);
    req.method = std::string(m[1]);
    req.target = std::string(m[2]);
    req.path = detail::decode_url(m[3], false);

    // Parse query text
    auto len = std::distance(m[4].first, m[4].second);
    if (len > 0) { detail::parse_query_text(m[4], req.params); }

    return true;
  }

  return false;
}

inline bool Server::write_response(Stream &strm, bool close_connection,
                                   const Request &req, Response &res) {
  assert(res.status != -1);

  if (400 <= res.status && error_handler_) { error_handler_(req, res); }

  detail::BufferStream bstrm;

  // Response line
  if (!bstrm.write_format("HTTP/1.1 %d %s\r\n", res.status,
                          detail::status_message(res.status))) {
    return false;
  }

  // Headers
  if (close_connection || req.get_header_value("Connection") == "close") {
    res.set_header("Connection", "close");
  }

  if (!close_connection && req.get_header_value("Connection") == "Keep-Alive") {
    res.set_header("Connection", "Keep-Alive");
  }

  if (!res.has_header("Content-Type") &&
      (!res.body.empty() || res.content_length_ > 0)) {
    res.set_header("Content-Type", "text/plain");
  }

  if (!res.has_header("Accept-Ranges") && req.method == "HEAD") {
    res.set_header("Accept-Ranges", "bytes");
  }

  std::string content_type;
  std::string boundary;

  if (req.ranges.size() > 1) {
    boundary = detail::make_multipart_data_boundary();

    auto it = res.headers.find("Content-Type");
    if (it != res.headers.end()) {
      content_type = it->second;
      res.headers.erase(it);
    }

    res.headers.emplace("Content-Type",
                        "multipart/byteranges; boundary=" + boundary);
  }

  if (res.body.empty()) {
    if (res.content_length_ > 0) {
      size_t length = 0;
      if (req.ranges.empty()) {
        length = res.content_length_;
      } else if (req.ranges.size() == 1) {
        auto offsets =
            detail::get_range_offset_and_length(req, res.content_length_, 0);
        auto offset = offsets.first;
        length = offsets.second;
        auto content_range = detail::make_content_range_header_field(
            offset, length, res.content_length_);
        res.set_header("Content-Range", content_range);
      } else {
        length = detail::get_multipart_ranges_data_length(req, res, boundary,
                                                          content_type);
      }
      res.set_header("Content-Length", std::to_string(length));
    } else {
      if (res.content_provider_) {
        res.set_header("Transfer-Encoding", "chunked");
      } else {
        res.set_header("Content-Length", "0");
      }
    }
  } else {
    if (req.ranges.empty()) {
      ;
    } else if (req.ranges.size() == 1) {
      auto offsets =
          detail::get_range_offset_and_length(req, res.body.size(), 0);
      auto offset = offsets.first;
      auto length = offsets.second;
      auto content_range = detail::make_content_range_header_field(
          offset, length, res.body.size());
      res.set_header("Content-Range", content_range);
      res.body = res.body.substr(offset, length);
    } else {
      res.body =
          detail::make_multipart_ranges_data(req, res, boundary, content_type);
    }

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
    // TODO: 'Accept-Encoding' has gzip, not gzip;q=0
    const auto &encodings = req.get_header_value("Accept-Encoding");
    if (encodings.find("gzip") != std::string::npos &&
        detail::can_compress(res.get_header_value("Content-Type"))) {
      if (detail::compress(res.body)) {
        res.set_header("Content-Encoding", "gzip");
      }
    }
#endif

    auto length = std::to_string(res.body.size());
    res.set_header("Content-Length", length);
  }

  if (!detail::write_headers(bstrm, res, Headers())) { return false; }

  // Flush buffer
  auto &data = bstrm.get_buffer();
  strm.write(data.data(), data.size());

  // Body
  if (req.method != "HEAD") {
    if (!res.body.empty()) {
      if (!strm.write(res.body)) { return false; }
    } else if (res.content_provider_) {
      if (!write_content_with_provider(strm, req, res, boundary,
                                       content_type)) {
        return false;
      }
    }
  }

  // Log
  if (logger_) { logger_(req, res); }

  return true;
}

inline bool
Server::write_content_with_provider(Stream &strm, const Request &req,
                                    Response &res, const std::string &boundary,
                                    const std::string &content_type) {
    auto is_shutting_down = [this]() {
        return this->svr_sock_ == nullptr;
    };

  if (res.content_length_) {
    if (req.ranges.empty()) {
      if (detail::write_content(strm, res.content_provider_, 0,
                                res.content_length_, is_shutting_down) < 0) {
        return false;
      }
    } else if (req.ranges.size() == 1) {
      auto offsets =
          detail::get_range_offset_and_length(req, res.content_length_, 0);
      auto offset = offsets.first;
      auto length = offsets.second;
      if (detail::write_content(strm, res.content_provider_, offset, length,
                                is_shutting_down) < 0) {
        return false;
      }
    } else {
      if (!detail::write_multipart_ranges_data(
              strm, req, res, boundary, content_type, is_shutting_down)) {
        return false;
      }
    }
  } else {
    if (detail::write_content_chunked(strm, res.content_provider_,
                                      is_shutting_down) < 0) {
      return false;
    }
  }
  return true;
}

inline bool Server::read_content(Stream &strm, Request &req, Response &res) {
  MultipartFormDataMap::iterator cur;
  if (read_content_core(
          strm, req, res,
          // Regular
          [&](const char *buf, size_t n) {
            if (req.body.size() + n > req.body.max_size()) { return false; }
            req.body.append(buf, n);
            return true;
          },
          // Multipart
          [&](const MultipartFormData &file) {
            cur = req.files.emplace(file.name, file);
            return true;
          },
          [&](const char *buf, size_t n) {
            auto &content = cur->second.content;
            if (content.size() + n > content.max_size()) { return false; }
            content.append(buf, n);
            return true;
          })) {
    const auto &content_type = req.get_header_value("Content-Type");
    if (!content_type.find("application/x-www-form-urlencoded")) {
      detail::parse_query_text(req.body, req.params);
    }
    return true;
  }
  return false;
}

inline bool Server::read_content_with_content_receiver(
    Stream &strm, Request &req, Response &res, ContentReceiver receiver,
    MultipartContentHeader multipart_header,
    ContentReceiver multipart_receiver) {
  return read_content_core(strm, req, res, receiver, multipart_header,
                           multipart_receiver);
}

inline bool Server::read_content_core(Stream &strm, Request &req, Response &res,
                                      ContentReceiver receiver,
                                      MultipartContentHeader mulitpart_header,
                                      ContentReceiver multipart_receiver) {
  detail::MultipartFormDataParser multipart_form_data_parser;
  ContentReceiver out;

  if (req.is_multipart_form_data()) {
    const auto &content_type = req.get_header_value("Content-Type");
    std::string boundary;
    if (!detail::parse_multipart_boundary(content_type, boundary)) {
      res.status = 400;
      return false;
    }

    multipart_form_data_parser.set_boundary(std::move(boundary));
    out = [&](const char *buf, size_t n) {
      /* For debug
      size_t pos = 0;
      while (pos < n) {
        auto read_size = std::min<size_t>(1, n - pos);
        auto ret = multipart_form_data_parser.parse(
            buf + pos, read_size, multipart_receiver, mulitpart_header);
        if (!ret) { return false; }
        pos += read_size;
      }
      return true;
      */
      return multipart_form_data_parser.parse(buf, n, multipart_receiver,
                                              mulitpart_header);
    };
  } else {
    out = receiver;
  }

  if (!detail::read_content(strm, req, payload_max_length_, res.status,
                            Progress(), out, true)) {
    return false;
  }

  if (req.is_multipart_form_data()) {
    if (!multipart_form_data_parser.is_valid()) {
      res.status = 400;
      return false;
    }
  }

  return true;
}

inline bool Server::handle_file_request(Request &req, Response &res,
                                        bool head) {
  for (const auto &kv : base_dirs_) {
    const auto &mount_point = kv.first;
    const auto &base_dir = kv.second;

    // Prefix match
    if (!req.path.find(mount_point)) {
      std::string sub_path = "/" + req.path.substr(mount_point.size());
      if (detail::is_valid_path(sub_path)) {
        auto path = base_dir + sub_path;
        if (path.back() == '/') { path += "index.html"; }

        if (detail::is_file(path)) {
          detail::read_file(path, res.body);
          auto type =
              detail::find_content_type(path, file_extension_and_mimetype_map_);
          if (type) { res.set_header("Content-Type", type); }
          res.status = 200;
          if (!head && file_request_handler_) {
            file_request_handler_(req, res);
          }
          return true;
        }
      }
    }
  }
  return false;
}

inline Socket *Server::create_server_socket(const char *host, int port, int socket_flags,
                                            SocketOptions socket_options) const {

    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = socket_flags;
    hints.ai_protocol = 0;

    auto service = std::to_string(port);

    if (swoole_coroutine_getaddrinfo(host, service.c_str(), &hints, &result)) {
        return nullptr;
    }

    Socket *sock = nullptr;
    for (auto rp = result; rp; rp = rp->ai_next) {
        sock = new Socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock->get_fd() == INVALID_SOCKET) {
            delete sock;
            continue;
        }
        if (tcp_nodelay_) {
            sock->set_option(IPPROTO_TCP, TCP_NODELAY, 1);
        }
        if (socket_options) {
            socket_options(sock->get_fd());
        }
        if (rp->ai_family == AF_INET6) {
            sock->set_option(IPPROTO_IPV6, IPV6_V6ONLY, 0);
        }
        if (!sock->bind(rp->ai_addr, static_cast<socklen_t>(rp->ai_addrlen))) {
            delete sock;
            return nullptr;
        }
        if (!sock->listen(512)) {
            delete sock;
            return nullptr;
        }
        break;
    }

    freeaddrinfo(result);
    return sock;
}

inline int Server::bind_internal(const char *host, int port, int socket_flags) {
    if (!is_valid()) {
        return -1;
    }

    svr_sock_ = create_server_socket(host, port, socket_flags, socket_options_);
    if (svr_sock_ == nullptr) {
        return -1;
    }

    if (port == 0) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getsockname(svr_sock_->get_fd(), reinterpret_cast<struct sockaddr *>(&addr), &addr_len) == -1) {
            return -1;
        }
        if (addr.ss_family == AF_INET) {
            return ntohs(reinterpret_cast<struct sockaddr_in *>(&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            return ntohs(reinterpret_cast<struct sockaddr_in6 *>(&addr)->sin6_port);
        } else {
            return -1;
        }
    } else {
        return port;
    }
}

struct CoroutineArg {
    Socket *client_socket;
    Server *this_;
};

inline bool Server::listen_internal() {

    if (!svr_sock_) {
        return false;
    }

    is_running_ = true;

    while (is_running_) {
        auto client_sock = svr_sock_->accept();
        if (client_sock) {
            auto arg = new CoroutineArg;
            arg->client_socket = client_sock;
            arg->this_ = this;
            Coroutine::create([](void *arg) {
                CoroutineArg *_arg = (CoroutineArg *) arg;
                _arg->this_->process_and_close_socket(_arg->client_socket);
                delete _arg;
            }, arg);
            continue;
        }
        if (svr_sock_->errCode == EMFILE || svr_sock_->errCode == ENFILE) {
            System::sleep(SW_ACCEPT_RETRY_TIME);
            continue;
        } else if (svr_sock_->errCode == ETIMEDOUT || svr_sock_->errCode == SW_ERROR_SSL_BAD_CLIENT) {
            continue;
        } else if (svr_sock_->errCode == ECANCELED) {
            break;
        } else {
            swWarn("accept failed, Error: %s[%d]", svr_sock_->errMsg, svr_sock_->errCode);
            break;
        }
    }

    is_running_ = false;
    return true;
}

inline bool Server::routing(Request &req, Response &res, Stream &strm) {
  // File handler
  bool is_head_request = req.method == "HEAD";
  if ((req.method == "GET" || is_head_request) &&
      handle_file_request(req, res, is_head_request)) {
    return true;
  }

  if (detail::expect_content(req)) {
    // Content reader handler
    {
      ContentReader reader(
          [&](ContentReceiver receiver) {
            return read_content_with_content_receiver(strm, req, res, receiver,
                                                      nullptr, nullptr);
          },
          [&](MultipartContentHeader header, ContentReceiver receiver) {
            return read_content_with_content_receiver(strm, req, res, nullptr,
                                                      header, receiver);
          });

      if (req.method == "POST") {
        if (dispatch_request_for_content_reader(
                req, res, reader, post_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "PUT") {
        if (dispatch_request_for_content_reader(
                req, res, reader, put_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "PATCH") {
        if (dispatch_request_for_content_reader(
                req, res, reader, patch_handlers_for_content_reader_)) {
          return true;
        }
      } else if (req.method == "DELETE") {
        if (dispatch_request_for_content_reader(
                req, res, reader, delete_handlers_for_content_reader_)) {
          return true;
        }
      }
    }

    // Read content into `req.body`
    if (!read_content(strm, req, res)) { return false; }
  }

  // Regular handler
  if (req.method == "GET" || req.method == "HEAD") {
    return dispatch_request(req, res, get_handlers_);
  } else if (req.method == "POST") {
    return dispatch_request(req, res, post_handlers_);
  } else if (req.method == "PUT") {
    return dispatch_request(req, res, put_handlers_);
  } else if (req.method == "DELETE") {
    return dispatch_request(req, res, delete_handlers_);
  } else if (req.method == "OPTIONS") {
    return dispatch_request(req, res, options_handlers_);
  } else if (req.method == "PATCH") {
    return dispatch_request(req, res, patch_handlers_);
  }

  res.status = 400;
  return false;
}

inline bool Server::dispatch_request(Request &req, Response &res,
                                     Handlers &handlers) {

  try {
    for (const auto &x : handlers) {
      const auto &pattern = x.first;
      const auto &handler = x.second;

      if (std::regex_match(req.path, req.matches, pattern)) {
        handler(req, res);
        return true;
      }
    }
  } catch (const std::exception &ex) {
    res.status = 500;
    res.set_header("EXCEPTION_WHAT", ex.what());
  } catch (...) {
    res.status = 500;
    res.set_header("EXCEPTION_WHAT", "UNKNOWN");
  }
  return false;
}

inline bool Server::dispatch_request_for_content_reader(
    Request &req, Response &res, ContentReader content_reader,
    HandlersForContentReader &handlers) {
  for (const auto &x : handlers) {
    const auto &pattern = x.first;
    const auto &handler = x.second;

    if (std::regex_match(req.path, req.matches, pattern)) {
      handler(req, res, content_reader);
      return true;
    }
  }
  return false;
}

inline bool
Server::process_request(Stream &strm, bool close_connection,
                        bool &connection_closed,
                        const std::function<void(Request &)> &setup_request) {
  std::array<char, 2048> buf{};

  detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

  // Connection has been closed on client
  if (!line_reader.getline()) { return false; }

  Request req;
  Response res;

  res.version = "HTTP/1.1";

  // Check if the request URI doesn't exceed the limit
  if (line_reader.size() > CPPHTTPLIB_REQUEST_URI_MAX_LENGTH) {
    Headers dummy;
    detail::read_headers(strm, dummy);
    res.status = 414;
    return write_response(strm, close_connection, req, res);
  }

  // Request line and headers
  if (!parse_request_line(line_reader.ptr(), req) ||
      !detail::read_headers(strm, req.headers)) {
    res.status = 400;
    return write_response(strm, close_connection, req, res);
  }

  if (req.get_header_value("Connection") == "close") {
    connection_closed = true;
  }

  if (req.version == "HTTP/1.0" &&
      req.get_header_value("Connection") != "Keep-Alive") {
    connection_closed = true;
  }

  strm.get_remote_ip_and_port(req.remote_addr, req.remote_port);
  req.set_header("REMOTE_ADDR", req.remote_addr);
  req.set_header("REMOTE_PORT", std::to_string(req.remote_port));

  if (req.has_header("Range")) {
    const auto &range_header_value = req.get_header_value("Range");
    if (!detail::parse_range_header(range_header_value, req.ranges)) {
      // TODO: error
    }
  }

  if (setup_request) { setup_request(req); }

  if (req.get_header_value("Expect") == "100-continue") {
    auto status = 100;
    if (expect_100_continue_handler_) {
      status = expect_100_continue_handler_(req, res);
    }
    switch (status) {
    case 100:
    case 417:
      strm.write_format("HTTP/1.1 %d %s\r\n\r\n", status,
                        detail::status_message(status));
      break;
    default: return write_response(strm, close_connection, req, res);
    }
  }

  // Rounting
  if (routing(req, res, strm)) {
    if (res.status == -1) { res.status = req.ranges.empty() ? 200 : 206; }
  } else {
    if (res.status == -1) { res.status = 404; }
  }

  return write_response(strm, close_connection, req, res);
}

inline bool Server::is_valid() const { return true; }

namespace detail {

template <typename T>
inline bool process_server_socket_core(socket_t sock,
                                       size_t keep_alive_max_count,
                                       T callback) {
  assert(keep_alive_max_count > 0);
  auto ret = false;
  auto count = keep_alive_max_count;
  while (count > 0 && keep_alive(sock)) {
    auto close_connection = count == 1;
    auto connection_closed = false;
    ret = callback(close_connection, connection_closed);
    if (!ret || connection_closed) { break; }
    count--;
  }
  return ret;
};

template <typename T>
inline bool process_server_socket(socket_t sock, size_t keep_alive_max_count,
                                  time_t read_timeout_sec,
                                  time_t read_timeout_usec,
                                  time_t write_timeout_sec,
                                  time_t write_timeout_usec, T callback) {
  return process_server_socket_core(
      sock, keep_alive_max_count,
      [&](bool close_connection, bool connection_closed) {
        SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
                          write_timeout_sec, write_timeout_usec);
        return callback(strm, close_connection, connection_closed);
      });
}

}

class CoSocketStream : public detail::SocketStream {
 public:
    CoSocketStream(Socket *sock, time_t read_timeout_sec, time_t read_timeout_usec, time_t write_timeout_sec,
                   time_t write_timeout_usec)
            : detail::SocketStream(sock->get_fd(), read_timeout_sec, read_timeout_usec, write_timeout_sec,
                                   write_timeout_usec) {
        sock_ = sock;
        sock->set_timeout((double) read_timeout_sec + ((double) read_timeout_usec / 1000000), swoole::SW_TIMEOUT_READ);
        sock->set_timeout((double) write_timeout_sec + ((double) write_timeout_usec / 1000000),
                          swoole::SW_TIMEOUT_WRITE);
    }
    ~CoSocketStream() {

    }
    bool is_readable() const {
        return true;
    }
    bool is_writable() const {
        return true;
    }
    ssize_t read(char *ptr, size_t size) {
        return sock_->recv_with_buffer(ptr, size);
    }
    ssize_t write(const char *ptr, size_t size) {
        return sock_->write(ptr, size);
    }
    void get_remote_ip_and_port(std::string &ip, int &port) const {
        swSocketAddress sa;
        sock_->getpeername(&sa);
        ip = std::string(swSocket_get_ip(sock_->get_type(), &sa));
        port = swSocket_get_port(sock_->get_type(), &sa);
    }
 private:
    Socket *sock_;
};

inline bool Server::process_and_close_socket(Socket *sock) {

    size_t keep_alive_max_count = keep_alive_max_count_;
    time_t read_timeout_sec = read_timeout_sec_;
    time_t read_timeout_usec = read_timeout_usec_;
    time_t write_timeout_sec = write_timeout_sec_;
    time_t write_timeout_usec = write_timeout_usec_;

    CoSocketStream strm(sock, read_timeout_sec, read_timeout_usec, write_timeout_sec, write_timeout_usec);

    assert(keep_alive_max_count > 0);

    auto ret = false;
    auto count = keep_alive_max_count;

    do {
        auto close_connection = count == 1;
        auto connection_closed = false;
        ret = process_request(strm, close_connection, connection_closed, nullptr);
        if (!ret || connection_closed) {
            break;
        }
        count--;
    } while (count > 0 && sock->check_liveness());

    sock->shutdown();
    sock->close();
    delete sock;

    return ret;
}

}
