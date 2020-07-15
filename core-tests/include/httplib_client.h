/**
 * httplib.h
 *
 * Copyright (c) 2020 Yuji Hirose. All rights reserved.
 * MIT License
 * GitHub: https://github.com/yhirose/cpp-httplib
*/

#pragma once

/*
 * Configuration
 */

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_MAX_COUNT
#define CPPHTTPLIB_KEEPALIVE_MAX_COUNT 5
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND 300
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_SECOND
#define CPPHTTPLIB_READ_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_READ_TIMEOUT_USECOND
#define CPPHTTPLIB_READ_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_WRITE_TIMEOUT_SECOND
#define CPPHTTPLIB_WRITE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_WRITE_TIMEOUT_USECOND
#define CPPHTTPLIB_WRITE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_SECOND
#define CPPHTTPLIB_IDLE_INTERVAL_SECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_USECOND
#ifdef _WIN32
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 10000
#else
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 0
#endif
#endif

#ifndef CPPHTTPLIB_REQUEST_URI_MAX_LENGTH
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_REDIRECT_MAX_COUNT
#define CPPHTTPLIB_REDIRECT_MAX_COUNT 20
#endif

#ifndef CPPHTTPLIB_PAYLOAD_MAX_LENGTH
#define CPPHTTPLIB_PAYLOAD_MAX_LENGTH ((std::numeric_limits<size_t>::max)())
#endif

#ifndef CPPHTTPLIB_TCP_NODELAY
#define CPPHTTPLIB_TCP_NODELAY false
#endif

#ifndef CPPHTTPLIB_RECV_BUFSIZ
#define CPPHTTPLIB_RECV_BUFSIZ size_t(4096u)
#endif

#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT                                           \
  ((std::max)(8u, std::thread::hardware_concurrency() > 0                      \
                      ? std::thread::hardware_concurrency() - 1                \
                      : 0))
#endif

// Prefer gnu::deprecated, otherwise gcc complains if we use
// [[deprecated]] together with pedantic.
#ifndef CPPHTTPLIB_DEPRECATED
#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(gnu::deprecated)
#define CPPHTTPLIB_DEPRECATED [[gnu::deprecated]]
#else
#if __has_cpp_attribute(deprecated)
#define CPPHTTPLIB_DEPRECATED [[deprecated]]
#else
#define CPPHTTPLIB_DEPRECATED
#endif
#endif
#else
#define CPPHTTPLIB_DEPRECATED
#endif
#endif

/*
 * Headers
 */

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#if defined(_MSC_VER)
#ifdef _WIN64
using ssize_t = __int64;
#else
using ssize_t = int;
#endif

#if _MSC_VER < 1900
#define snprintf _snprintf_s
#endif
#endif // _MSC_VER

#ifndef S_ISREG
#define S_ISREG(m) (((m)&S_IFREG) == S_IFREG)
#endif // S_ISREG

#ifndef S_ISDIR
#define S_ISDIR(m) (((m)&S_IFDIR) == S_IFDIR)
#endif // S_ISDIR

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif // strcasecmp

using socket_t = SOCKET;
#ifdef CPPHTTPLIB_USE_POLL
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#endif

#else // not _WIN32

#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef CPPHTTPLIB_USE_POLL
#include <poll.h>
#endif
#include <csignal>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

using socket_t = int;
#define INVALID_SOCKET (-1)
#endif //_WIN32

#include <array>
#include <atomic>
#include <cassert>
#include <climits>
#include <condition_variable>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iomanip>
#include <iostream>
#include <sstream>

// #if OPENSSL_VERSION_NUMBER < 0x1010100fL
// #error Sorry, OpenSSL versions prior to 1.1.1 are not supported
// #endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/crypto.h>
inline const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1) {
  return M_ASN1_STRING_data(asn1);
}
#endif
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif
/*
 * Declaration
 */
namespace httplib {

const std::string USER_AGENT = "cpp-httplib/0.7";

namespace detail {

struct ci {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return std::lexicographical_compare(
        s1.begin(), s1.end(), s2.begin(), s2.end(),
        [](char c1, char c2) { return ::tolower(c1) < ::tolower(c2); });
  }
};

} // namespace detail

using Headers = std::multimap<std::string, std::string, detail::ci>;

using Params = std::multimap<std::string, std::string>;
using Match = std::smatch;

using Progress = std::function<bool(uint64_t current, uint64_t total)>;

struct Response;
using ResponseHandler = std::function<bool(const Response &response)>;

struct MultipartFormData {
  std::string name;
  std::string content;
  std::string filename;
  std::string content_type;
};
using MultipartFormDataItems = std::vector<MultipartFormData>;
using MultipartFormDataMap = std::multimap<std::string, MultipartFormData>;

class DataSink {
public:
  DataSink() : os(&sb_), sb_(*this) {}

  DataSink(const DataSink &) = delete;
  DataSink &operator=(const DataSink &) = delete;
  DataSink(DataSink &&) = delete;
  DataSink &operator=(DataSink &&) = delete;

  std::function<void(const char *data, size_t data_len)> write;
  std::function<void()> done;
  std::function<bool()> is_writable;
  std::ostream os;

private:
  class data_sink_streambuf : public std::streambuf {
  public:
    data_sink_streambuf(DataSink &sink) : sink_(sink) {}

  protected:
    std::streamsize xsputn(const char *s, std::streamsize n) {
      sink_.write(s, static_cast<size_t>(n));
      return n;
    }

  private:
    DataSink &sink_;
  };

  data_sink_streambuf sb_;
};

using ContentProvider =
    std::function<bool(size_t offset, size_t length, DataSink &sink)>;

using ChunkedContentProvider =
    std::function<bool(size_t offset, DataSink &sink)>;

using ContentReceiver =
    std::function<bool(const char *data, size_t data_length)>;

using MultipartContentHeader =
    std::function<bool(const MultipartFormData &file)>;

using Range = std::pair<ssize_t, ssize_t>;
using Ranges = std::vector<Range>;

struct Request {
  std::string method;
  std::string path;
  Headers headers;
  std::string body;

  std::string remote_addr;
  int remote_port = -1;

  // for server
  std::string version;
  std::string target;
  Params params;
  MultipartFormDataMap files;
  Ranges ranges;
  Match matches;

  // for client
  size_t redirect_count = CPPHTTPLIB_REDIRECT_MAX_COUNT;
  ResponseHandler response_handler;
  ContentReceiver content_receiver;
  size_t content_length = 0;
  ContentProvider content_provider;
  Progress progress;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  const SSL *ssl;
#endif

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  bool has_param(const char *key) const;
  std::string get_param_value(const char *key, size_t id = 0) const;
  size_t get_param_value_count(const char *key) const;

  bool is_multipart_form_data() const;

  bool has_file(const char *key) const;
  MultipartFormData get_file_value(const char *key) const;

  // private members...
  size_t authorization_count_ = 0;
};

struct Response {
  std::string version;
  int status = -1;
  Headers headers;
  std::string body;

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  void set_redirect(const char *url, int status = 302);
  void set_content(const char *s, size_t n, const char *content_type);
  void set_content(std::string s, const char *content_type);

  void set_content_provider(
      size_t length, ContentProvider provider,
      std::function<void()> resource_releaser = [] {});

  void set_chunked_content_provider(
      ChunkedContentProvider provider,
      std::function<void()> resource_releaser = [] {});

  Response() = default;
  Response(const Response &) = default;
  Response &operator=(const Response &) = default;
  Response(Response &&) = default;
  Response &operator=(Response &&) = default;
  ~Response() {
    if (content_provider_resource_releaser_) {
      content_provider_resource_releaser_();
    }
  }

  // private members...
  size_t content_length_ = 0;
  ContentProvider content_provider_;
  std::function<void()> content_provider_resource_releaser_;
};

class Stream {
public:
  virtual ~Stream() = default;

  virtual bool is_readable() const = 0;
  virtual bool is_writable() const = 0;

  virtual ssize_t read(char *ptr, size_t size) = 0;
  virtual ssize_t write(const char *ptr, size_t size) = 0;
  virtual void get_remote_ip_and_port(std::string &ip, int &port) const = 0;

  template <typename... Args>
  ssize_t write_format(const char *fmt, const Args &... args);
  ssize_t write(const char *ptr);
  ssize_t write(const std::string &s);
};

using Logger = std::function<void(const Request &, const Response &)>;

using SocketOptions = std::function<void(socket_t sock)>;

inline void default_socket_options(socket_t sock) {
  int yes = 1;
#ifdef _WIN32
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&yes),
             sizeof(yes));
  setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
             reinterpret_cast<char *>(&yes), sizeof(yes));
#else
#ifdef SO_REUSEPORT
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<void *>(&yes),
             sizeof(yes));
#else
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&yes),
             sizeof(yes));
#endif
#endif
}

class Client {
public:
  explicit Client(const std::string &host);

  explicit Client(const std::string &host, int port);

  explicit Client(const std::string &host, int port,
                  const std::string &client_cert_path,
                  const std::string &client_key_path);

  virtual ~Client();

  virtual bool is_valid() const;

  std::shared_ptr<Response> Get(const char *path);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers);

  std::shared_ptr<Response> Get(const char *path, Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                Progress progress);

  std::shared_ptr<Response> Get(const char *path,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response>
  Get(const char *path, ContentReceiver content_receiver, Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver,
                                Progress progress);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver);

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver,
                                Progress progress);

  std::shared_ptr<Response> Head(const char *path);

  std::shared_ptr<Response> Head(const char *path, const Headers &headers);

  std::shared_ptr<Response> Post(const char *path);

  std::shared_ptr<Response> Post(const char *path, const std::string &body,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const std::string &body,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type);

  std::shared_ptr<Response> Post(const char *path, const Params &params);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const Params &params);

  std::shared_ptr<Response> Post(const char *path,
                                 const MultipartFormDataItems &items);

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const MultipartFormDataItems &items);

  std::shared_ptr<Response> Put(const char *path);

  std::shared_ptr<Response> Put(const char *path, const std::string &body,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const std::string &body,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type);

  std::shared_ptr<Response> Put(const char *path, const Params &params);

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const Params &params);

  std::shared_ptr<Response> Patch(const char *path, const std::string &body,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  const std::string &body,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type);

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type);

  std::shared_ptr<Response> Delete(const char *path);

  std::shared_ptr<Response> Delete(const char *path, const std::string &body,
                                   const char *content_type);

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers);

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers,
                                   const std::string &body,
                                   const char *content_type);

  std::shared_ptr<Response> Options(const char *path);

  std::shared_ptr<Response> Options(const char *path, const Headers &headers);

  bool send(const Request &req, Response &res);

  size_t is_socket_open() const;

  void stop();

  void set_tcp_nodelay(bool on);
  void set_socket_options(SocketOptions socket_options);

  CPPHTTPLIB_DEPRECATED void set_timeout_sec(time_t timeout_sec);
  void set_connection_timeout(time_t sec, time_t usec = 0);
  void set_read_timeout(time_t sec, time_t usec = 0);
  void set_write_timeout(time_t sec, time_t usec = 0);

  void set_basic_auth(const char *username, const char *password);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_digest_auth(const char *username, const char *password);
#endif

  void set_keep_alive(bool on);
  void set_follow_location(bool on);

  void set_compress(bool on);

  void set_decompress(bool on);

  void set_interface(const char *intf);

  void set_proxy(const char *host, int port);
  void set_proxy_basic_auth(const char *username, const char *password);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_proxy_digest_auth(const char *username, const char *password);
#endif

  void set_logger(Logger logger);

protected:
  struct Socket {
    socket_t sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSL *ssl = nullptr;
#endif

    bool is_open() const { return sock != INVALID_SOCKET; }
  };

  virtual bool create_and_connect_socket(Socket &socket);
  virtual void close_socket(Socket &socket, bool process_socket_ret);

  bool process_request(Stream &strm, const Request &req, Response &res,
                       bool close_connection);

  // Socket endoint information
  const std::string host_;
  const int port_;
  const std::string host_and_port_;

  // Current open socket
  Socket socket_;
  mutable std::mutex socket_mutex_;
  std::recursive_mutex request_mutex_;

  // Settings
  std::string client_cert_path_;
  std::string client_key_path_;

  time_t connection_timeout_sec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND;
  time_t connection_timeout_usec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND;
  time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;

  std::string basic_auth_username_;
  std::string basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string digest_auth_username_;
  std::string digest_auth_password_;
#endif

  bool keep_alive_ = false;
  bool follow_location_ = false;

  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  SocketOptions socket_options_ = nullptr;

  bool compress_ = false;
  bool decompress_ = true;

  std::string interface_;

  std::string proxy_host_;
  int proxy_port_;

  std::string proxy_basic_auth_username_;
  std::string proxy_basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string proxy_digest_auth_username_;
  std::string proxy_digest_auth_password_;
#endif

  Logger logger_;

  void copy_settings(const Client &rhs) {
    client_cert_path_ = rhs.client_cert_path_;
    client_key_path_ = rhs.client_key_path_;
    connection_timeout_sec_ = rhs.connection_timeout_sec_;
    read_timeout_sec_ = rhs.read_timeout_sec_;
    read_timeout_usec_ = rhs.read_timeout_usec_;
    write_timeout_sec_ = rhs.write_timeout_sec_;
    write_timeout_usec_ = rhs.write_timeout_usec_;
    basic_auth_username_ = rhs.basic_auth_username_;
    basic_auth_password_ = rhs.basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    digest_auth_username_ = rhs.digest_auth_username_;
    digest_auth_password_ = rhs.digest_auth_password_;
#endif
    keep_alive_ = rhs.keep_alive_;
    follow_location_ = rhs.follow_location_;
    tcp_nodelay_ = rhs.tcp_nodelay_;
    socket_options_ = rhs.socket_options_;
    compress_ = rhs.compress_;
    decompress_ = rhs.decompress_;
    interface_ = rhs.interface_;
    proxy_host_ = rhs.proxy_host_;
    proxy_port_ = rhs.proxy_port_;
    proxy_basic_auth_username_ = rhs.proxy_basic_auth_username_;
    proxy_basic_auth_password_ = rhs.proxy_basic_auth_password_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    proxy_digest_auth_username_ = rhs.proxy_digest_auth_username_;
    proxy_digest_auth_password_ = rhs.proxy_digest_auth_password_;
#endif
    logger_ = rhs.logger_;
  }

private:
  socket_t create_client_socket() const;
  bool read_response_line(Stream &strm, Response &res);
  bool write_request(Stream &strm, const Request &req, bool close_connection);
  bool redirect(const Request &req, Response &res);
  bool handle_request(Stream &strm, const Request &req, Response &res,
                      bool close_connection);

  std::shared_ptr<Response> send_with_content_provider(
      const char *method, const char *path, const Headers &headers,
      const std::string &body, size_t content_length,
      ContentProvider content_provider, const char *content_type);

  virtual bool process_socket(Socket &socket,
                              std::function<bool(Stream &strm)> callback);
  virtual bool is_ssl() const;
};

inline void Get(std::vector<Request> &requests, const char *path,
                const Headers &headers) {
  Request req;
  req.method = "GET";
  req.path = path;
  req.headers = headers;
  requests.emplace_back(std::move(req));
}

inline void Get(std::vector<Request> &requests, const char *path) {
  Get(requests, path, Headers());
}

inline void Post(std::vector<Request> &requests, const char *path,
                 const Headers &headers, const std::string &body,
                 const char *content_type) {
  Request req;
  req.method = "POST";
  req.path = path;
  req.headers = headers;
  if (content_type) { req.headers.emplace("Content-Type", content_type); }
  req.body = body;
  requests.emplace_back(std::move(req));
}

inline void Post(std::vector<Request> &requests, const char *path,
                 const std::string &body, const char *content_type) {
  Post(requests, path, Headers(), body, content_type);
}

inline void Post(std::vector<Request> &requests, const char *path,
                 size_t content_length, ContentProvider content_provider,
                 const char *content_type) {
  Request req;
  req.method = "POST";
  req.headers = Headers();
  req.path = path;
  req.content_length = content_length;
  req.content_provider = content_provider;

  if (content_type) { req.headers.emplace("Content-Type", content_type); }

  requests.emplace_back(std::move(req));
}

class Client2 {
public:
  explicit Client2(const char *scheme_host_port)
      : Client2(scheme_host_port, std::string(), std::string()) {}

  explicit Client2(const char *scheme_host_port,
                   const std::string &client_cert_path,
                   const std::string &client_key_path) {
    const static std::regex re(R"(^(https?)://([^:/?#]+)(?::(\d+))?)");

    std::cmatch m;
    if (std::regex_match(scheme_host_port, m, re)) {
      auto scheme = m[1].str();
      auto host = m[2].str();
      auto port_str = m[3].str();

      auto port = !port_str.empty() ? std::stoi(port_str)
                                    : (scheme == "https" ? 443 : 80);

      if (scheme == "https") {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        is_ssl_ = true;
        cli_ = std::make_shared<SSLClient>(host.c_str(), port, client_cert_path,
                                           client_key_path);
#endif
      } else {
        cli_ = std::make_shared<Client>(host.c_str(), port, client_cert_path,
                                        client_key_path);
      }
    }
  }

  ~Client2() {}

  bool is_valid() const { return cli_ != nullptr; }

  std::shared_ptr<Response> Get(const char *path) { return cli_->Get(path); }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers) {
    return cli_->Get(path, headers);
  }

  std::shared_ptr<Response> Get(const char *path, Progress progress) {
    return cli_->Get(path, progress);
  }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                Progress progress) {
    return cli_->Get(path, headers, progress);
  }

  std::shared_ptr<Response> Get(const char *path,
                                ContentReceiver content_receiver) {
    return cli_->Get(path, content_receiver);
  }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver) {
    return cli_->Get(path, headers, content_receiver);
  }

  std::shared_ptr<Response>
  Get(const char *path, ContentReceiver content_receiver, Progress progress) {
    return cli_->Get(path, content_receiver, progress);
  }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ContentReceiver content_receiver,
                                Progress progress) {
    return cli_->Get(path, headers, content_receiver, progress);
  }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver) {
    return cli_->Get(path, headers, response_handler, content_receiver);
  }

  std::shared_ptr<Response> Get(const char *path, const Headers &headers,
                                ResponseHandler response_handler,
                                ContentReceiver content_receiver,
                                Progress progress) {
    return cli_->Get(path, headers, response_handler, content_receiver,
                     progress);
  }

  std::shared_ptr<Response> Head(const char *path) { return cli_->Head(path); }

  std::shared_ptr<Response> Head(const char *path, const Headers &headers) {
    return cli_->Head(path, headers);
  }

  std::shared_ptr<Response> Post(const char *path) { return cli_->Post(path); }

  std::shared_ptr<Response> Post(const char *path, const std::string &body,
                                 const char *content_type) {
    return cli_->Post(path, body, content_type);
  }

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const std::string &body,
                                 const char *content_type) {
    return cli_->Post(path, headers, body, content_type);
  }

  std::shared_ptr<Response> Post(const char *path, size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type) {
    return cli_->Post(path, content_length, content_provider, content_type);
  }

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 size_t content_length,
                                 ContentProvider content_provider,
                                 const char *content_type) {
    return cli_->Post(path, headers, content_length, content_provider,
                      content_type);
  }

  std::shared_ptr<Response> Post(const char *path, const Params &params) {
    return cli_->Post(path, params);
  }

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const Params &params) {
    return cli_->Post(path, headers, params);
  }

  std::shared_ptr<Response> Post(const char *path,
                                 const MultipartFormDataItems &items) {
    return cli_->Post(path, items);
  }

  std::shared_ptr<Response> Post(const char *path, const Headers &headers,
                                 const MultipartFormDataItems &items) {
    return cli_->Post(path, headers, items);
  }

  std::shared_ptr<Response> Put(const char *path) { return cli_->Put(path); }

  std::shared_ptr<Response> Put(const char *path, const std::string &body,
                                const char *content_type) {
    return cli_->Put(path, body, content_type);
  }

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const std::string &body,
                                const char *content_type) {
    return cli_->Put(path, headers, body, content_type);
  }

  std::shared_ptr<Response> Put(const char *path, size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type) {
    return cli_->Put(path, content_length, content_provider, content_type);
  }

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                size_t content_length,
                                ContentProvider content_provider,
                                const char *content_type) {
    return cli_->Put(path, headers, content_length, content_provider,
                     content_type);
  }

  std::shared_ptr<Response> Put(const char *path, const Params &params) {
    return cli_->Put(path, params);
  }

  std::shared_ptr<Response> Put(const char *path, const Headers &headers,
                                const Params &params) {
    return cli_->Put(path, headers, params);
  }

  std::shared_ptr<Response> Patch(const char *path, const std::string &body,
                                  const char *content_type) {
    return cli_->Patch(path, body, content_type);
  }

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  const std::string &body,
                                  const char *content_type) {
    return cli_->Patch(path, headers, body, content_type);
  }

  std::shared_ptr<Response> Patch(const char *path, size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type) {
    return cli_->Patch(path, content_length, content_provider, content_type);
  }

  std::shared_ptr<Response> Patch(const char *path, const Headers &headers,
                                  size_t content_length,
                                  ContentProvider content_provider,
                                  const char *content_type) {
    return cli_->Patch(path, headers, content_length, content_provider,
                       content_type);
  }

  std::shared_ptr<Response> Delete(const char *path) {
    return cli_->Delete(path);
  }

  std::shared_ptr<Response> Delete(const char *path, const std::string &body,
                                   const char *content_type) {
    return cli_->Delete(path, body, content_type);
  }

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers) {
    return cli_->Delete(path, headers);
  }

  std::shared_ptr<Response> Delete(const char *path, const Headers &headers,
                                   const std::string &body,
                                   const char *content_type) {
    return cli_->Delete(path, headers, body, content_type);
  }

  std::shared_ptr<Response> Options(const char *path) {
    return cli_->Options(path);
  }

  std::shared_ptr<Response> Options(const char *path, const Headers &headers) {
    return cli_->Options(path, headers);
  }

  bool send(const Request &req, Response &res) { return cli_->send(req, res); }

  bool is_socket_open() { return cli_->is_socket_open(); }

  void stop() { cli_->stop(); }

  void set_tcp_nodelay(bool on) {
    cli_->set_tcp_nodelay(on);
  }

  void set_socket_options(SocketOptions socket_options) {
    cli_->set_socket_options(socket_options);
  }

  Client2 &set_connection_timeout(time_t sec, time_t usec) {
    cli_->set_connection_timeout(sec, usec);
    return *this;
  }

  Client2 &set_read_timeout(time_t sec, time_t usec) {
    cli_->set_read_timeout(sec, usec);
    return *this;
  }

  Client2 &set_basic_auth(const char *username, const char *password) {
    cli_->set_basic_auth(username, password);
    return *this;
  }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  Client2 &set_digest_auth(const char *username, const char *password) {
    cli_->set_digest_auth(username, password);
    return *this;
  }
#endif

  Client2 &set_keep_alive(bool on) {
    cli_->set_keep_alive(on);
    return *this;
  }

  Client2 &set_follow_location(bool on) {
    cli_->set_follow_location(on);
    return *this;
  }

  Client2 &set_compress(bool on) {
    cli_->set_compress(on);
    return *this;
  }

  Client2 &set_decompress(bool on) {
    cli_->set_decompress(on);
    return *this;
  }

  Client2 &set_interface(const char *intf) {
    cli_->set_interface(intf);
    return *this;
  }

  Client2 &set_proxy(const char *host, int port) {
    cli_->set_proxy(host, port);
    return *this;
  }

  Client2 &set_proxy_basic_auth(const char *username, const char *password) {
    cli_->set_proxy_basic_auth(username, password);
    return *this;
  }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  Client2 &set_proxy_digest_auth(const char *username, const char *password) {
    cli_->set_proxy_digest_auth(username, password);
    return *this;
  }
#endif

  Client2 &set_logger(Logger logger) {
    cli_->set_logger(logger);
    return *this;
  }

  // SSL
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  Client2 &set_ca_cert_path(const char *ca_cert_file_path,
                            const char *ca_cert_dir_path = nullptr) {
    if (is_ssl_) {
      static_cast<SSLClient &>(*cli_).set_ca_cert_path(ca_cert_file_path,
                                                       ca_cert_dir_path);
    }
    return *this;
  }

  Client2 &set_ca_cert_store(X509_STORE *ca_cert_store) {
    if (is_ssl_) {
      static_cast<SSLClient &>(*cli_).set_ca_cert_store(ca_cert_store);
    }
    return *this;
  }

  Client2 &enable_server_certificate_verification(bool enabled) {
    if (is_ssl_) {
      static_cast<SSLClient &>(*cli_).enable_server_certificate_verification(
          enabled);
    }
    return *this;
  }

  long get_openssl_verify_result() const {
    if (is_ssl_) {
      return static_cast<SSLClient &>(*cli_).get_openssl_verify_result();
    }
    return -1; // NOTE: -1 doesn't match any of X509_V_ERR_???
  }

  SSL_CTX *ssl_context() const {
    if (is_ssl_) { return static_cast<SSLClient &>(*cli_).ssl_context(); }
    return nullptr;
  }
#endif

private:
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool is_ssl_ = false;
#endif
  std::shared_ptr<Client> cli_;
};

// ----------------------------------------------------------------------------

/*
 * Implementation
 */

namespace detail {

inline bool is_hex(char c, int &v) {
  if (0x20 <= c && isdigit(c)) {
    v = c - '0';
    return true;
  } else if ('A' <= c && c <= 'F') {
    v = c - 'A' + 10;
    return true;
  } else if ('a' <= c && c <= 'f') {
    v = c - 'a' + 10;
    return true;
  }
  return false;
}

inline bool from_hex_to_i(const std::string &s, size_t i, size_t cnt,
                          int &val) {
  if (i >= s.size()) { return false; }

  val = 0;
  for (; cnt; i++, cnt--) {
    if (!s[i]) { return false; }
    int v = 0;
    if (is_hex(s[i], v)) {
      val = val * 16 + v;
    } else {
      return false;
    }
  }
  return true;
}

inline std::string from_i_to_hex(size_t n) {
  const char *charset = "0123456789abcdef";
  std::string ret;
  do {
    ret = charset[n & 15] + ret;
    n >>= 4;
  } while (n > 0);
  return ret;
}

inline size_t to_utf8(int code, char *buff) {
  if (code < 0x0080) {
    buff[0] = (code & 0x7F);
    return 1;
  } else if (code < 0x0800) {
    buff[0] = static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
    buff[1] = static_cast<char>(0x80 | (code & 0x3F));
    return 2;
  } else if (code < 0xD800) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0xE000) { // D800 - DFFF is invalid...
    return 0;
  } else if (code < 0x10000) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0x110000) {
    buff[0] = static_cast<char>(0xF0 | ((code >> 18) & 0x7));
    buff[1] = static_cast<char>(0x80 | ((code >> 12) & 0x3F));
    buff[2] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[3] = static_cast<char>(0x80 | (code & 0x3F));
    return 4;
  }

  // NOTREACHED
  return 0;
}

// NOTE: This code came up with the following stackoverflow post:
// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
inline std::string base64_encode(const std::string &in) {
  static const auto lookup =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  out.reserve(in.size());

  int val = 0;
  int valb = -6;

  for (auto c : in) {
    val = (val << 8) + static_cast<uint8_t>(c);
    valb += 8;
    while (valb >= 0) {
      out.push_back(lookup[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }

  if (valb > -6) { out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]); }

  while (out.size() % 4) {
    out.push_back('=');
  }

  return out;
}

inline bool is_file(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

inline bool is_valid_path(const std::string &path) {
  size_t level = 0;
  size_t i = 0;

  // Skip slash
  while (i < path.size() && path[i] == '/') {
    i++;
  }

  while (i < path.size()) {
    // Read component
    auto beg = i;
    while (i < path.size() && path[i] != '/') {
      i++;
    }

    auto len = i - beg;
    assert(len > 0);

    if (!path.compare(beg, len, ".")) {
      ;
    } else if (!path.compare(beg, len, "..")) {
      if (level == 0) { return false; }
      level--;
    } else {
      level++;
    }

    // Skip slash
    while (i < path.size() && path[i] == '/') {
      i++;
    }
  }

  return true;
}

inline void read_file(const std::string &path, std::string &out) {
  std::ifstream fs(path, std::ios_base::binary);
  fs.seekg(0, std::ios_base::end);
  auto size = fs.tellg();
  fs.seekg(0);
  out.resize(static_cast<size_t>(size));
  fs.read(&out[0], static_cast<std::streamsize>(size));
}

inline std::string file_extension(const std::string &path) {
  std::smatch m;
  static auto re = std::regex("\\.([a-zA-Z0-9]+)$");
  if (std::regex_search(path, m, re)) { return m[1].str(); }
  return std::string();
}

template <class Fn> void split(const char *b, const char *e, char d, Fn fn) {
  int i = 0;
  int beg = 0;

  while (e ? (b + i != e) : (b[i] != '\0')) {
    if (b[i] == d) {
      fn(&b[beg], &b[i]);
      beg = i + 1;
    }
    i++;
  }

  if (i) { fn(&b[beg], &b[i]); }
}

// NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
// to store data. The call can set memory on stack for performance.
class stream_line_reader {
public:
  stream_line_reader(Stream &strm, char *fixed_buffer, size_t fixed_buffer_size)
      : strm_(strm), fixed_buffer_(fixed_buffer),
        fixed_buffer_size_(fixed_buffer_size) {}

  const char *ptr() const {
    if (glowable_buffer_.empty()) {
      return fixed_buffer_;
    } else {
      return glowable_buffer_.data();
    }
  }

  size_t size() const {
    if (glowable_buffer_.empty()) {
      return fixed_buffer_used_size_;
    } else {
      return glowable_buffer_.size();
    }
  }

  bool end_with_crlf() const {
    auto end = ptr() + size();
    return size() >= 2 && end[-2] == '\r' && end[-1] == '\n';
  }

  bool getline() {
    fixed_buffer_used_size_ = 0;
    glowable_buffer_.clear();

    for (size_t i = 0;; i++) {
      char byte;
      auto n = strm_.read(&byte, 1);

      if (n < 0) {
        return false;
      } else if (n == 0) {
        if (i == 0) {
          return false;
        } else {
          break;
        }
      }

      append(byte);

      if (byte == '\n') { break; }
    }

    return true;
  }

private:
  void append(char c) {
    if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1) {
      fixed_buffer_[fixed_buffer_used_size_++] = c;
      fixed_buffer_[fixed_buffer_used_size_] = '\0';
    } else {
      if (glowable_buffer_.empty()) {
        assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
        glowable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
      }
      glowable_buffer_ += c;
    }
  }

  Stream &strm_;
  char *fixed_buffer_;
  const size_t fixed_buffer_size_;
  size_t fixed_buffer_used_size_ = 0;
  std::string glowable_buffer_;
};

inline int close_socket(socket_t sock) {
#ifdef _WIN32
  return closesocket(sock);
#else
  return close(sock);
#endif
}

template <typename T> inline ssize_t handle_EINTR(T fn) {
  ssize_t res = false;
  while (true) {
    res = fn();
    if (res < 0 && errno == EINTR) { continue; }
    break;
  }
  return res;
}

inline ssize_t select_read(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
  struct pollfd pfd_read;
  pfd_read.fd = sock;
  pfd_read.events = POLLIN;

  auto timeout = static_cast<int>(sec * 1000 + usec);

  return handle_EINTR([&]() { return poll(&pfd_read, 1, timeout); });
#else
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  timeval tv;
  tv.tv_sec = static_cast<long>(sec);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

  return handle_EINTR([&]() {
    return select(static_cast<int>(sock + 1), &fds, nullptr, nullptr, &tv);
  });
#endif
}

inline ssize_t select_write(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
  struct pollfd pfd_read;
  pfd_read.fd = sock;
  pfd_read.events = POLLOUT;

  auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

  return handle_EINTR([&]() { return poll(&pfd_read, 1, timeout); });
#else
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  timeval tv;
  tv.tv_sec = static_cast<long>(sec);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

  return handle_EINTR([&]() {
    return select(static_cast<int>(sock + 1), nullptr, &fds, nullptr, &tv);
  });
#endif
}

inline bool wait_until_socket_is_ready(socket_t sock, time_t sec, time_t usec) {
#ifdef CPPHTTPLIB_USE_POLL
  struct pollfd pfd_read;
  pfd_read.fd = sock;
  pfd_read.events = POLLIN | POLLOUT;

  auto timeout = static_cast<int>(sec * 1000 + usec);

  auto poll_res = handle_EINTR([&]() { return poll(&pfd_read, 1, timeout); });

  if (poll_res > 0 && pfd_read.revents & (POLLIN | POLLOUT)) {
    int error = 0;
    socklen_t len = sizeof(error);
    auto res = getsockopt(sock, SOL_SOCKET, SO_ERROR,
                          reinterpret_cast<char *>(&error), &len);
    return res >= 0 && !error;
  }
  return false;
#else
  fd_set fdsr;
  FD_ZERO(&fdsr);
  FD_SET(sock, &fdsr);

  auto fdsw = fdsr;
  auto fdse = fdsr;

  timeval tv;
  tv.tv_sec = static_cast<long>(sec);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

  auto ret = handle_EINTR([&]() {
    return select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv);
  });

  if (ret > 0 && (FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))) {
    int error = 0;
    socklen_t len = sizeof(error);
    return getsockopt(sock, SOL_SOCKET, SO_ERROR,
                      reinterpret_cast<char *>(&error), &len) >= 0 &&
           !error;
  }
  return false;
#endif
}

class SocketStream : public Stream {
public:
  SocketStream(socket_t sock, time_t read_timeout_sec, time_t read_timeout_usec,
               time_t write_timeout_sec, time_t write_timeout_usec);
  ~SocketStream() override;

  bool is_readable() const override;
  bool is_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;

private:
  socket_t sock_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLSocketStream : public Stream {
public:
  SSLSocketStream(socket_t sock, SSL *ssl, time_t read_timeout_sec,
                  time_t read_timeout_usec, time_t write_timeout_sec,
                  time_t write_timeout_usec);
  ~SSLSocketStream() override;

  bool is_readable() const override;
  bool is_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;

private:
  socket_t sock_;
  SSL *ssl_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
};
#endif

class BufferStream : public Stream {
public:
  BufferStream() = default;
  ~BufferStream() override = default;

  bool is_readable() const override;
  bool is_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;

  const std::string &get_buffer() const;

private:
  std::string buffer;
  size_t position = 0;
};

inline bool keep_alive(socket_t sock) {
  using namespace std::chrono;
  auto start = steady_clock::now();
  while (true) {
    auto val = select_read(sock, 0, 10000);
    if (val < 0) {
      return false;
    } else if (val == 0) {
      auto current = steady_clock::now();
      auto duration = duration_cast<milliseconds>(current - start);
      auto timeout = CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND * 100 +
                     CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND;
      if (duration.count() > timeout) { return false; }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else {
      return true;
    }
  }
}


template <typename T>
inline bool process_client_socket(socket_t sock, time_t read_timeout_sec,
                                  time_t read_timeout_usec,
                                  time_t write_timeout_sec,
                                  time_t write_timeout_usec, T callback) {
  SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
                    write_timeout_sec, write_timeout_usec);
  return callback(strm);
}

inline int shutdown_socket(socket_t sock) {
#ifdef _WIN32
  return shutdown(sock, SD_BOTH);
#else
  return shutdown(sock, SHUT_RDWR);
#endif
}

template <typename BindOrConnect>
socket_t create_socket(const char *host, int port, int socket_flags,
                       bool tcp_nodelay, SocketOptions socket_options,
                       BindOrConnect bind_or_connect) {
  // Get address info
  struct addrinfo hints;
  struct addrinfo *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = socket_flags;
  hints.ai_protocol = 0;

  auto service = std::to_string(port);

  if (getaddrinfo(host, service.c_str(), &hints, &result)) {
    return INVALID_SOCKET;
  }

  for (auto rp = result; rp; rp = rp->ai_next) {
    // Create a socket
#ifdef _WIN32
    auto sock = WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol,
                           nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    /**
     * Since the WSA_FLAG_NO_HANDLE_INHERIT is only supported on Windows 7 SP1
     * and above the socket creation fails on older Windows Systems.
     *
     * Let's try to create a socket the old way in this case.
     *
     * Reference:
     * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
     *
     * WSA_FLAG_NO_HANDLE_INHERIT:
     * This flag is supported on Windows 7 with SP1, Windows Server 2008 R2 with
     * SP1, and later
     *
     */
    if (sock == INVALID_SOCKET) {
      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    }
#else
    auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
    if (sock == INVALID_SOCKET) { continue; }

#ifndef _WIN32
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) { continue; }
#endif

    if (tcp_nodelay) {
      int yes = 1;
      setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&yes),
                 sizeof(yes));
    }

    if (socket_options) { socket_options(sock); }

    if (rp->ai_family == AF_INET6) {
      int no = 0;
      setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char *>(&no),
                 sizeof(no));
    }

    // bind or connect
    if (bind_or_connect(sock, *rp)) {
      freeaddrinfo(result);
      return sock;
    }

    close_socket(sock);
  }

  freeaddrinfo(result);
  return INVALID_SOCKET;
}

inline void set_nonblocking(socket_t sock, bool nonblocking) {
#ifdef _WIN32
  auto flags = nonblocking ? 1UL : 0UL;
  ioctlsocket(sock, FIONBIO, &flags);
#else
  auto flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL,
        nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif
}

inline bool is_connection_error() {
#ifdef _WIN32
  return WSAGetLastError() != WSAEWOULDBLOCK;
#else
  return errno != EINPROGRESS;
#endif
}

inline bool bind_ip_address(socket_t sock, const char *host) {
  struct addrinfo hints;
  struct addrinfo *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if (getaddrinfo(host, "0", &hints, &result)) { return false; }

  auto ret = false;
  for (auto rp = result; rp; rp = rp->ai_next) {
    const auto &ai = *rp;
    if (!::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen))) {
      ret = true;
      break;
    }
  }

  freeaddrinfo(result);
  return ret;
}

#ifndef _WIN32
inline std::string if2ip(const std::string &ifn) {
  struct ifaddrs *ifap;
  getifaddrs(&ifap);
  for (auto ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifn == ifa->ifa_name) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        auto sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN)) {
          freeifaddrs(ifap);
          return std::string(buf, INET_ADDRSTRLEN);
        }
      }
    }
  }
  freeifaddrs(ifap);
  return std::string();
}
#endif

inline socket_t create_client_socket(const char *host, int port,
                                     bool tcp_nodelay,
                                     SocketOptions socket_options,
                                     time_t timeout_sec, time_t timeout_usec,
                                     const std::string &intf) {
  return create_socket(
      host, port, 0, tcp_nodelay, socket_options,
      [&](socket_t sock, struct addrinfo &ai) -> bool {
        if (!intf.empty()) {
#ifndef _WIN32
          auto ip = if2ip(intf);
          if (ip.empty()) { ip = intf; }
          if (!bind_ip_address(sock, ip.c_str())) { return false; }
#endif
        }

        set_nonblocking(sock, true);

        auto ret =
            ::connect(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen));
        if (ret < 0) {
          if (is_connection_error() ||
              !wait_until_socket_is_ready(sock, timeout_sec, timeout_usec)) {
            close_socket(sock);
            return false;
          }
        }

        set_nonblocking(sock, false);
        return true;
      });
}

inline void get_remote_ip_and_port(const struct sockaddr_storage &addr,
                                   socklen_t addr_len, std::string &ip,
                                   int &port) {
  if (addr.ss_family == AF_INET) {
    port = ntohs(reinterpret_cast<const struct sockaddr_in *>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    port =
        ntohs(reinterpret_cast<const struct sockaddr_in6 *>(&addr)->sin6_port);
  }

  std::array<char, NI_MAXHOST> ipstr{};
  if (!getnameinfo(reinterpret_cast<const struct sockaddr *>(&addr), addr_len,
                   ipstr.data(), static_cast<socklen_t>(ipstr.size()), nullptr,
                   0, NI_NUMERICHOST)) {
    ip = ipstr.data();
  }
}

inline void get_remote_ip_and_port(socket_t sock, std::string &ip, int &port) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  if (!getpeername(sock, reinterpret_cast<struct sockaddr *>(&addr),
                   &addr_len)) {
    get_remote_ip_and_port(addr, addr_len, ip, port);
  }
}

inline const char *
find_content_type(const std::string &path,
                  const std::map<std::string, std::string> &user_data) {
  auto ext = file_extension(path);

  auto it = user_data.find(ext);
  if (it != user_data.end()) { return it->second.c_str(); }

  if (ext == "txt") {
    return "text/plain";
  } else if (ext == "html" || ext == "htm") {
    return "text/html";
  } else if (ext == "css") {
    return "text/css";
  } else if (ext == "jpeg" || ext == "jpg") {
    return "image/jpg";
  } else if (ext == "png") {
    return "image/png";
  } else if (ext == "gif") {
    return "image/gif";
  } else if (ext == "svg") {
    return "image/svg+xml";
  } else if (ext == "ico") {
    return "image/x-icon";
  } else if (ext == "json") {
    return "application/json";
  } else if (ext == "pdf") {
    return "application/pdf";
  } else if (ext == "js") {
    return "application/javascript";
  } else if (ext == "wasm") {
    return "application/wasm";
  } else if (ext == "xml") {
    return "application/xml";
  } else if (ext == "xhtml") {
    return "application/xhtml+xml";
  }
  return nullptr;
}

inline const char *status_message(int status) {
  switch (status) {
  case 100: return "Continue";
  case 101: return "Switching Protocol";
  case 102: return "Processing";
  case 103: return "Early Hints";
  case 200: return "OK";
  case 201: return "Created";
  case 202: return "Accepted";
  case 203: return "Non-Authoritative Information";
  case 204: return "No Content";
  case 205: return "Reset Content";
  case 206: return "Partial Content";
  case 207: return "Multi-Status";
  case 208: return "Already Reported";
  case 226: return "IM Used";
  case 300: return "Multiple Choice";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 304: return "Not Modified";
  case 305: return "Use Proxy";
  case 306: return "unused";
  case 307: return "Temporary Redirect";
  case 308: return "Permanent Redirect";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 402: return "Payment Required";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 406: return "Not Acceptable";
  case 407: return "Proxy Authentication Required";
  case 408: return "Request Timeout";
  case 409: return "Conflict";
  case 410: return "Gone";
  case 411: return "Length Required";
  case 412: return "Precondition Failed";
  case 413: return "Payload Too Large";
  case 414: return "URI Too Long";
  case 415: return "Unsupported Media Type";
  case 416: return "Range Not Satisfiable";
  case 417: return "Expectation Failed";
  case 418: return "I'm a teapot";
  case 421: return "Misdirected Request";
  case 422: return "Unprocessable Entity";
  case 423: return "Locked";
  case 424: return "Failed Dependency";
  case 425: return "Too Early";
  case 426: return "Upgrade Required";
  case 428: return "Precondition Required";
  case 429: return "Too Many Requests";
  case 431: return "Request Header Fields Too Large";
  case 451: return "Unavailable For Legal Reasons";
  case 501: return "Not Implemented";
  case 502: return "Bad Gateway";
  case 503: return "Service Unavailable";
  case 504: return "Gateway Timeout";
  case 505: return "HTTP Version Not Supported";
  case 506: return "Variant Also Negotiates";
  case 507: return "Insufficient Storage";
  case 508: return "Loop Detected";
  case 510: return "Not Extended";
  case 511: return "Network Authentication Required";

  default:
  case 500: return "Internal Server Error";
  }
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
inline bool can_compress(const std::string &content_type) {
  return !content_type.find("text/") || content_type == "image/svg+xml" ||
         content_type == "application/javascript" ||
         content_type == "application/json" ||
         content_type == "application/xml" ||
         content_type == "application/xhtml+xml";
}

inline bool compress(std::string &content) {
  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;

  auto ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                          Z_DEFAULT_STRATEGY);
  if (ret != Z_OK) { return false; }

  strm.avail_in = static_cast<decltype(strm.avail_in)>(content.size());
  strm.next_in =
      const_cast<Bytef *>(reinterpret_cast<const Bytef *>(content.data()));

  std::string compressed;

  std::array<char, 16384> buff{};
  do {
    strm.avail_out = buff.size();
    strm.next_out = reinterpret_cast<Bytef *>(buff.data());
    ret = deflate(&strm, Z_FINISH);
    assert(ret != Z_STREAM_ERROR);
    compressed.append(buff.data(), buff.size() - strm.avail_out);
  } while (strm.avail_out == 0);

  assert(ret == Z_STREAM_END);
  assert(strm.avail_in == 0);

  content.swap(compressed);

  deflateEnd(&strm);
  return true;
}

class decompressor {
public:
  decompressor() {
    std::memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // 15 is the value of wbits, which should be at the maximum possible value
    // to ensure that any gzip stream can be decoded. The offset of 32 specifies
    // that the stream type should be automatically detected either gzip or
    // deflate.
    is_valid_ = inflateInit2(&strm, 32 + 15) == Z_OK;
  }

  ~decompressor() { inflateEnd(&strm); }

  bool is_valid() const { return is_valid_; }

  template <typename T>
  bool decompress(const char *data, size_t data_length, T callback) {
    int ret = Z_OK;

    strm.avail_in = static_cast<decltype(strm.avail_in)>(data_length);
    strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    std::array<char, 16384> buff{};
    do {
      strm.avail_out = buff.size();
      strm.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = inflate(&strm, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);
      switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR: inflateEnd(&strm); return false;
      }

      if (!callback(buff.data(), buff.size() - strm.avail_out)) {
        return false;
      }
    } while (strm.avail_out == 0);

    return ret == Z_OK || ret == Z_STREAM_END;
  }

private:
  bool is_valid_;
  z_stream strm;
};
#endif

inline bool has_header(const Headers &headers, const char *key) {
  return headers.find(key) != headers.end();
}

inline const char *get_header_value(const Headers &headers, const char *key,
                                    size_t id = 0, const char *def = nullptr) {
  auto rng = headers.equal_range(key);
  auto it = rng.first;
  std::advance(it, static_cast<ssize_t>(id));
  if (it != rng.second) { return it->second.c_str(); }
  return def;
}

inline uint64_t get_header_value_uint64(const Headers &headers, const char *key,
                                        uint64_t def = 0) {
  auto it = headers.find(key);
  if (it != headers.end()) {
    return std::strtoull(it->second.data(), nullptr, 10);
  }
  return def;
}

inline void parse_header(const char *beg, const char *end, Headers &headers) {
  auto p = beg;
  while (p < end && *p != ':') {
    p++;
  }
  if (p < end) {
    auto key_end = p;
    p++; // skip ':'
    while (p < end && (*p == ' ' || *p == '\t')) {
      p++;
    }
    if (p < end) {
      auto val_begin = p;
      while (p < end) {
        p++;
      }
      headers.emplace(std::string(beg, key_end), std::string(val_begin, end));
    }
  }
}

inline bool read_headers(Stream &strm, Headers &headers) {
  const auto bufsiz = 2048;
  char buf[bufsiz];
  stream_line_reader line_reader(strm, buf, bufsiz);

  for (;;) {
    if (!line_reader.getline()) { return false; }

    // Check if the line ends with CRLF.
    if (line_reader.end_with_crlf()) {
      // Blank line indicates end of headers.
      if (line_reader.size() == 2) { break; }
    } else {
      continue; // Skip invalid line.
    }

    // Skip trailing spaces and tabs.
    auto end = line_reader.ptr() + line_reader.size() - 2;
    while (line_reader.ptr() < end && (end[-1] == ' ' || end[-1] == '\t')) {
      end--;
    }

    parse_header(line_reader.ptr(), end, headers);
  }

  return true;
}

inline bool read_content_with_length(Stream &strm, uint64_t len,
                                     Progress progress, ContentReceiver out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];

  uint64_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return false; }

    if (!out(buf, static_cast<size_t>(n))) { return false; }

    r += static_cast<uint64_t>(n);

    if (progress) {
      if (!progress(r, len)) { return false; }
    }
  }

  return true;
}

inline void skip_content_with_length(Stream &strm, uint64_t len) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  uint64_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return; }
    r += static_cast<uint64_t>(n);
  }
}

inline bool read_content_without_length(Stream &strm, ContentReceiver out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  for (;;) {
    auto n = strm.read(buf, CPPHTTPLIB_RECV_BUFSIZ);
    if (n < 0) {
      return false;
    } else if (n == 0) {
      return true;
    }
    if (!out(buf, static_cast<size_t>(n))) { return false; }
  }

  return true;
}

inline bool read_content_chunked(Stream &strm, ContentReceiver out) {
  const auto bufsiz = 16;
  char buf[bufsiz];

  stream_line_reader line_reader(strm, buf, bufsiz);

  if (!line_reader.getline()) { return false; }

  unsigned long chunk_len;
  while (true) {
    char *end_ptr;

    chunk_len = std::strtoul(line_reader.ptr(), &end_ptr, 16);

    if (end_ptr == line_reader.ptr()) { return false; }
    if (chunk_len == ULONG_MAX) { return false; }

    if (chunk_len == 0) { break; }

    if (!read_content_with_length(strm, chunk_len, nullptr, out)) {
      return false;
    }

    if (!line_reader.getline()) { return false; }

    if (strcmp(line_reader.ptr(), "\r\n")) { break; }

    if (!line_reader.getline()) { return false; }
  }

  if (chunk_len == 0) {
    // Reader terminator after chunks
    if (!line_reader.getline() || strcmp(line_reader.ptr(), "\r\n"))
      return false;
  }

  return true;
}

inline bool is_chunked_transfer_encoding(const Headers &headers) {
  return !strcasecmp(get_header_value(headers, "Transfer-Encoding", 0, ""),
                     "chunked");
}

template <typename T>
bool read_content(Stream &strm, T &x, size_t payload_max_length, int &status,
                  Progress progress, ContentReceiver receiver,
                  bool decompress) {

  ContentReceiver out = [&](const char *buf, size_t n) {
    return receiver(buf, n);
  };

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
  decompressor decompressor;
#endif

  if (decompress) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
    std::string content_encoding = x.get_header_value("Content-Encoding");
    if (content_encoding.find("gzip") != std::string::npos ||
        content_encoding.find("deflate") != std::string::npos) {
      if (!decompressor.is_valid()) {
        status = 500;
        return false;
      }

      out = [&](const char *buf, size_t n) {
        return decompressor.decompress(buf, n, [&](const char *buf, size_t n) {
          return receiver(buf, n);
        });
      };
    }
#else
    if (x.get_header_value("Content-Encoding") == "gzip") {
      status = 415;
      return false;
    }
#endif
  }

  auto ret = true;
  auto exceed_payload_max_length = false;

  if (is_chunked_transfer_encoding(x.headers)) {
    ret = read_content_chunked(strm, out);
  } else if (!has_header(x.headers, "Content-Length")) {
    ret = read_content_without_length(strm, out);
  } else {
    auto len = get_header_value_uint64(x.headers, "Content-Length", 0);
    if (len > payload_max_length) {
      exceed_payload_max_length = true;
      skip_content_with_length(strm, len);
      ret = false;
    } else if (len > 0) {
      ret = read_content_with_length(strm, len, progress, out);
    }
  }

  if (!ret) { status = exceed_payload_max_length ? 413 : 400; }
  return ret;
}

template <typename T>
inline ssize_t write_headers(Stream &strm, const T &info,
                             const Headers &headers) {
  ssize_t write_len = 0;
  for (const auto &x : info.headers) {
    if (x.first == "EXCEPTION_WHAT") { continue; }
    auto len =
        strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
    if (len < 0) { return len; }
    write_len += len;
  }
  for (const auto &x : headers) {
    auto len =
        strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
    if (len < 0) { return len; }
    write_len += len;
  }
  auto len = strm.write("\r\n");
  if (len < 0) { return len; }
  write_len += len;
  return write_len;
}

inline bool write_data(Stream &strm, const char *d, size_t l) {
  size_t offset = 0;
  while (offset < l) {
    auto length = strm.write(d + offset, l - offset);
    if (length < 0) { return false; }
    offset += static_cast<size_t>(length);
  }
  return true;
}

template <typename T>
inline ssize_t write_content(Stream &strm, ContentProvider content_provider,
                             size_t offset, size_t length, T is_shutting_down) {
  size_t begin_offset = offset;
  size_t end_offset = offset + length;

  auto ok = true;

  DataSink data_sink;
  data_sink.write = [&](const char *d, size_t l) {
    if (ok) {
      offset += l;
      if (!write_data(strm, d, l)) { ok = false; }
    }
  };
  data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

  while (ok && offset < end_offset && !is_shutting_down()) {
    if (!content_provider(offset, end_offset - offset, data_sink)) {
      return -1;
    }
    if (!ok) { return -1; }
  }

  return static_cast<ssize_t>(offset - begin_offset);
}

template <typename T>
inline ssize_t write_content_chunked(Stream &strm,
                                     ContentProvider content_provider,
                                     T is_shutting_down) {
  size_t offset = 0;
  auto data_available = true;
  ssize_t total_written_length = 0;

  auto ok = true;

  DataSink data_sink;
  data_sink.write = [&](const char *d, size_t l) {
    if (ok) {
      data_available = l > 0;
      offset += l;

      // Emit chunked response header and footer for each chunk
      auto chunk = from_i_to_hex(l) + "\r\n" + std::string(d, l) + "\r\n";
      if (write_data(strm, chunk.data(), chunk.size())) {
        total_written_length += chunk.size();
      } else {
        ok = false;
      }
    }
  };
  data_sink.done = [&](void) {
    data_available = false;
    if (ok) {
      static const std::string done_marker("0\r\n\r\n");
      if (write_data(strm, done_marker.data(), done_marker.size())) {
        total_written_length += done_marker.size();
      } else {
        ok = false;
      }
    }
  };
  data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

  while (data_available && !is_shutting_down()) {
    if (!content_provider(offset, 0, data_sink)) { return -1; }
    if (!ok) { return -1; }
  }

  return total_written_length;
}

template <typename T>
inline bool redirect(T &cli, const Request &req, Response &res,
                     const std::string &path) {
  Request new_req = req;
  new_req.path = path;
  new_req.redirect_count -= 1;

  if (res.status == 303 && (req.method != "GET" && req.method != "HEAD")) {
    new_req.method = "GET";
    new_req.body.clear();
    new_req.headers.clear();
  }

  Response new_res;

  auto ret = cli.send(new_req, new_res);
  if (ret) { res = new_res; }
  return ret;
}

inline std::string encode_url(const std::string &s) {
  std::string result;

  for (size_t i = 0; s[i]; i++) {
    switch (s[i]) {
    case ' ': result += "%20"; break;
    case '+': result += "%2B"; break;
    case '\r': result += "%0D"; break;
    case '\n': result += "%0A"; break;
    case '\'': result += "%27"; break;
    case ',': result += "%2C"; break;
    // case ':': result += "%3A"; break; // ok? probably...
    case ';': result += "%3B"; break;
    default:
      auto c = static_cast<uint8_t>(s[i]);
      if (c >= 0x80) {
        result += '%';
        char hex[4];
        auto len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
        assert(len == 2);
        result.append(hex, static_cast<size_t>(len));
      } else {
        result += s[i];
      }
      break;
    }
  }

  return result;
}

inline std::string decode_url(const std::string &s,
                              bool convert_plus_to_space) {
  std::string result;

  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 1 < s.size()) {
      if (s[i + 1] == 'u') {
        int val = 0;
        if (from_hex_to_i(s, i + 2, 4, val)) {
          // 4 digits Unicode codes
          char buff[4];
          size_t len = to_utf8(val, buff);
          if (len > 0) { result.append(buff, len); }
          i += 5; // 'u0000'
        } else {
          result += s[i];
        }
      } else {
        int val = 0;
        if (from_hex_to_i(s, i + 1, 2, val)) {
          // 2 digits hex codes
          result += static_cast<char>(val);
          i += 2; // '00'
        } else {
          result += s[i];
        }
      }
    } else if (convert_plus_to_space && s[i] == '+') {
      result += ' ';
    } else {
      result += s[i];
    }
  }

  return result;
}

inline std::string params_to_query_str(const Params &params) {
  std::string query;

  for (auto it = params.begin(); it != params.end(); ++it) {
    if (it != params.begin()) { query += "&"; }
    query += it->first;
    query += "=";
    query += detail::encode_url(it->second);
  }

  return query;
}

inline void parse_query_text(const std::string &s, Params &params) {
  split(&s[0], &s[s.size()], '&', [&](const char *b, const char *e) {
    std::string key;
    std::string val;
    split(b, e, '=', [&](const char *b2, const char *e2) {
      if (key.empty()) {
        key.assign(b2, e2);
      } else {
        val.assign(b2, e2);
      }
    });
    params.emplace(decode_url(key, true), decode_url(val, true));
  });
}

inline bool parse_multipart_boundary(const std::string &content_type,
                                     std::string &boundary) {
  auto pos = content_type.find("boundary=");
  if (pos == std::string::npos) { return false; }
  boundary = content_type.substr(pos + 9);
  if (boundary.length() >= 2 && boundary.front() == '"' &&
      boundary.back() == '"') {
    boundary = boundary.substr(1, boundary.size() - 2);
  }
  return !boundary.empty();
}

inline bool parse_range_header(const std::string &s, Ranges &ranges) {
  static auto re_first_range = std::regex(R"(bytes=(\d*-\d*(?:,\s*\d*-\d*)*))");
  std::smatch m;
  if (std::regex_match(s, m, re_first_range)) {
    auto pos = static_cast<size_t>(m.position(1));
    auto len = static_cast<size_t>(m.length(1));
    bool all_valid_ranges = true;
    split(&s[pos], &s[pos + len], ',', [&](const char *b, const char *e) {
      if (!all_valid_ranges) return;
      static auto re_another_range = std::regex(R"(\s*(\d*)-(\d*))");
      std::cmatch cm;
      if (std::regex_match(b, e, cm, re_another_range)) {
        ssize_t first = -1;
        if (!cm.str(1).empty()) {
          first = static_cast<ssize_t>(std::stoll(cm.str(1)));
        }

        ssize_t last = -1;
        if (!cm.str(2).empty()) {
          last = static_cast<ssize_t>(std::stoll(cm.str(2)));
        }

        if (first != -1 && last != -1 && first > last) {
          all_valid_ranges = false;
          return;
        }
        ranges.emplace_back(std::make_pair(first, last));
      }
    });
    return all_valid_ranges;
  }
  return false;
}

class MultipartFormDataParser {
public:
  MultipartFormDataParser() = default;

  void set_boundary(std::string &&boundary) { boundary_ = boundary; }

  bool is_valid() const { return is_valid_; }

  template <typename T, typename U>
  bool parse(const char *buf, size_t n, T content_callback, U header_callback) {
    static const std::regex re_content_type(R"(^Content-Type:\s*(.*?)\s*$)",
                                            std::regex_constants::icase);

    static const std::regex re_content_disposition(
        "^Content-Disposition:\\s*form-data;\\s*name=\"(.*?)\"(?:;\\s*filename="
        "\"(.*?)\")?\\s*$",
        std::regex_constants::icase);
    static const std::string dash_ = "--";
    static const std::string crlf_ = "\r\n";

    buf_.append(buf, n); // TODO: performance improvement

    while (!buf_.empty()) {
      switch (state_) {
      case 0: { // Initial boundary
        auto pattern = dash_ + boundary_ + crlf_;
        if (pattern.size() > buf_.size()) { return true; }
        auto pos = buf_.find(pattern);
        if (pos != 0) { return false; }
        buf_.erase(0, pattern.size());
        off_ += pattern.size();
        state_ = 1;
        break;
      }
      case 1: { // New entry
        clear_file_info();
        state_ = 2;
        break;
      }
      case 2: { // Headers
        auto pos = buf_.find(crlf_);
        while (pos != std::string::npos) {
          // Empty line
          if (pos == 0) {
            if (!header_callback(file_)) {
              is_valid_ = false;
              return false;
            }
            buf_.erase(0, crlf_.size());
            off_ += crlf_.size();
            state_ = 3;
            break;
          }

          auto header = buf_.substr(0, pos);
          {
            std::smatch m;
            if (std::regex_match(header, m, re_content_type)) {
              file_.content_type = m[1];
            } else if (std::regex_match(header, m, re_content_disposition)) {
              file_.name = m[1];
              file_.filename = m[2];
            }
          }

          buf_.erase(0, pos + crlf_.size());
          off_ += pos + crlf_.size();
          pos = buf_.find(crlf_);
        }
        if (state_ != 3) { return true; }
        break;
      }
      case 3: { // Body
        {
          auto pattern = crlf_ + dash_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = buf_.find(pattern);
          if (pos == std::string::npos) {
            pos = buf_.size();
            while (pos > 0) {
              auto c = buf_[pos - 1];
              if (c != '\r' && c != '\n' && c != '-') { break; }
              pos--;
            }
          }

          if (!content_callback(buf_.data(), pos)) {
            is_valid_ = false;
            return false;
          }

          off_ += pos;
          buf_.erase(0, pos);
        }

        {
          auto pattern = crlf_ + dash_ + boundary_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = buf_.find(pattern);
          if (pos != std::string::npos) {
            if (!content_callback(buf_.data(), pos)) {
              is_valid_ = false;
              return false;
            }

            off_ += pos + pattern.size();
            buf_.erase(0, pos + pattern.size());
            state_ = 4;
          } else {
            if (!content_callback(buf_.data(), pattern.size())) {
              is_valid_ = false;
              return false;
            }

            off_ += pattern.size();
            buf_.erase(0, pattern.size());
          }
        }
        break;
      }
      case 4: { // Boundary
        if (crlf_.size() > buf_.size()) { return true; }
        if (buf_.find(crlf_) == 0) {
          buf_.erase(0, crlf_.size());
          off_ += crlf_.size();
          state_ = 1;
        } else {
          auto pattern = dash_ + crlf_;
          if (pattern.size() > buf_.size()) { return true; }
          if (buf_.find(pattern) == 0) {
            buf_.erase(0, pattern.size());
            off_ += pattern.size();
            is_valid_ = true;
            state_ = 5;
          } else {
            return true;
          }
        }
        break;
      }
      case 5: { // Done
        is_valid_ = false;
        return false;
      }
      }
    }

    return true;
  }

private:
  void clear_file_info() {
    file_.name.clear();
    file_.filename.clear();
    file_.content_type.clear();
  }

  std::string boundary_;

  std::string buf_;
  size_t state_ = 0;
  bool is_valid_ = false;
  size_t off_ = 0;
  MultipartFormData file_;
};

inline std::string to_lower(const char *beg, const char *end) {
  std::string out;
  auto it = beg;
  while (it != end) {
    out += static_cast<char>(::tolower(*it));
    it++;
  }
  return out;
}

inline std::string make_multipart_data_boundary() {
  static const char data[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::random_device seed_gen;
  std::mt19937 engine(seed_gen());

  std::string result = "--cpp-httplib-multipart-data-";

  for (auto i = 0; i < 16; i++) {
    result += data[engine() % (sizeof(data) - 1)];
  }

  return result;
}

inline std::pair<size_t, size_t>
get_range_offset_and_length(const Request &req, size_t content_length,
                            size_t index) {
  auto r = req.ranges[index];

  if (r.first == -1 && r.second == -1) {
    return std::make_pair(0, content_length);
  }

  auto slen = static_cast<ssize_t>(content_length);

  if (r.first == -1) {
    r.first = slen - r.second;
    r.second = slen - 1;
  }

  if (r.second == -1) { r.second = slen - 1; }

  return std::make_pair(r.first, r.second - r.first + 1);
}

inline std::string make_content_range_header_field(size_t offset, size_t length,
                                                   size_t content_length) {
  std::string field = "bytes ";
  field += std::to_string(offset);
  field += "-";
  field += std::to_string(offset + length - 1);
  field += "/";
  field += std::to_string(content_length);
  return field;
}

template <typename SToken, typename CToken, typename Content>
bool process_multipart_ranges_data(const Request &req, Response &res,
                                   const std::string &boundary,
                                   const std::string &content_type,
                                   SToken stoken, CToken ctoken,
                                   Content content) {
  for (size_t i = 0; i < req.ranges.size(); i++) {
    ctoken("--");
    stoken(boundary);
    ctoken("\r\n");
    if (!content_type.empty()) {
      ctoken("Content-Type: ");
      stoken(content_type);
      ctoken("\r\n");
    }

    auto offsets = get_range_offset_and_length(req, res.body.size(), i);
    auto offset = offsets.first;
    auto length = offsets.second;

    ctoken("Content-Range: ");
    stoken(make_content_range_header_field(offset, length, res.body.size()));
    ctoken("\r\n");
    ctoken("\r\n");
    if (!content(offset, length)) { return false; }
    ctoken("\r\n");
  }

  ctoken("--");
  stoken(boundary);
  ctoken("--\r\n");

  return true;
}

inline std::string make_multipart_ranges_data(const Request &req, Response &res,
                                              const std::string &boundary,
                                              const std::string &content_type) {
  std::string data;

  process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data += token; },
      [&](const char *token) { data += token; },
      [&](size_t offset, size_t length) {
        data += res.body.substr(offset, length);
        return true;
      });

  return data;
}

inline size_t
get_multipart_ranges_data_length(const Request &req, Response &res,
                                 const std::string &boundary,
                                 const std::string &content_type) {
  size_t data_length = 0;

  process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data_length += token.size(); },
      [&](const char *token) { data_length += strlen(token); },
      [&](size_t /*offset*/, size_t length) {
        data_length += length;
        return true;
      });

  return data_length;
}

template <typename T>
inline bool write_multipart_ranges_data(Stream &strm, const Request &req,
                                        Response &res,
                                        const std::string &boundary,
                                        const std::string &content_type,
                                        T is_shutting_down) {
  return process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { strm.write(token); },
      [&](const char *token) { strm.write(token); },
      [&](size_t offset, size_t length) {
        return write_content(strm, res.content_provider_, offset, length,
                             is_shutting_down) >= 0;
      });
}

inline std::pair<size_t, size_t>
get_range_offset_and_length(const Request &req, const Response &res,
                            size_t index) {
  auto r = req.ranges[index];

  if (r.second == -1) {
    r.second = static_cast<ssize_t>(res.content_length_) - 1;
  }

  return std::make_pair(r.first, r.second - r.first + 1);
}

inline bool expect_content(const Request &req) {
  if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" ||
      req.method == "PRI" ||
      (req.method == "DELETE" && req.has_header("Content-Length"))) {
    return true;
  }
  // TODO: check if Content-Length is set
  return false;
}

inline bool has_crlf(const char *s) {
  auto p = s;
  while (*p) {
    if (*p == '\r' || *p == '\n') { return true; }
    p++;
  }
  return false;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
template <typename CTX, typename Init, typename Update, typename Final>
inline std::string message_digest(const std::string &s, Init init,
                                  Update update, Final final,
                                  size_t digest_length) {
  using namespace std;

  std::vector<unsigned char> md(digest_length, 0);
  CTX ctx;
  init(&ctx);
  update(&ctx, s.data(), s.size());
  final(md.data(), &ctx);

  stringstream ss;
  for (auto c : md) {
    ss << setfill('0') << setw(2) << hex << (unsigned int)c;
  }
  return ss.str();
}

inline std::string MD5(const std::string &s) {
  return message_digest<MD5_CTX>(s, MD5_Init, MD5_Update, MD5_Final,
                                 MD5_DIGEST_LENGTH);
}

inline std::string SHA_256(const std::string &s) {
  return message_digest<SHA256_CTX>(s, SHA256_Init, SHA256_Update, SHA256_Final,
                                    SHA256_DIGEST_LENGTH);
}

inline std::string SHA_512(const std::string &s) {
  return message_digest<SHA512_CTX>(s, SHA512_Init, SHA512_Update, SHA512_Final,
                                    SHA512_DIGEST_LENGTH);
}
#endif

#ifdef _WIN32
class WSInit {
public:
  WSInit() {
    WSADATA wsaData;
    WSAStartup(0x0002, &wsaData);
  }

  ~WSInit() { WSACleanup(); }
};

static WSInit wsinit_;
#endif

} // namespace detail

// Header utilities
inline std::pair<std::string, std::string> make_range_header(Ranges ranges) {
  std::string field = "bytes=";
  auto i = 0;
  for (auto r : ranges) {
    if (i != 0) { field += ", "; }
    if (r.first != -1) { field += std::to_string(r.first); }
    field += '-';
    if (r.second != -1) { field += std::to_string(r.second); }
    i++;
  }
  return std::make_pair("Range", field);
}

inline std::pair<std::string, std::string>
make_basic_authentication_header(const std::string &username,
                                 const std::string &password,
                                 bool is_proxy = false) {
  auto field = "Basic " + detail::base64_encode(username + ":" + password);
  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline std::pair<std::string, std::string> make_digest_authentication_header(
    const Request &req, const std::map<std::string, std::string> &auth,
    size_t cnonce_count, const std::string &cnonce, const std::string &username,
    const std::string &password, bool is_proxy = false) {
  using namespace std;

  string nc;
  {
    stringstream ss;
    ss << setfill('0') << setw(8) << hex << cnonce_count;
    nc = ss.str();
  }

  auto qop = auth.at("qop");
  if (qop.find("auth-int") != std::string::npos) {
    qop = "auth-int";
  } else {
    qop = "auth";
  }

  std::string algo = "MD5";
  if (auth.find("algorithm") != auth.end()) { algo = auth.at("algorithm"); }

  string response;
  {
    auto H = algo == "SHA-256"
                 ? detail::SHA_256
                 : algo == "SHA-512" ? detail::SHA_512 : detail::MD5;

    auto A1 = username + ":" + auth.at("realm") + ":" + password;

    auto A2 = req.method + ":" + req.path;
    if (qop == "auth-int") { A2 += ":" + H(req.body); }

    response = H(H(A1) + ":" + auth.at("nonce") + ":" + nc + ":" + cnonce +
                 ":" + qop + ":" + H(A2));
  }

  auto field = "Digest username=\"" + username + "\", realm=\"" +
               auth.at("realm") + "\", nonce=\"" + auth.at("nonce") +
               "\", uri=\"" + req.path + "\", algorithm=" + algo +
               ", qop=" + qop + ", nc=\"" + nc + "\", cnonce=\"" + cnonce +
               "\", response=\"" + response + "\"";

  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}
#endif

inline bool parse_www_authenticate(const Response &res,
                                   std::map<std::string, std::string> &auth,
                                   bool is_proxy) {
  auto auth_key = is_proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
  if (res.has_header(auth_key)) {
    static auto re = std::regex(R"~((?:(?:,\s*)?(.+?)=(?:"(.*?)"|([^,]*))))~");
    auto s = res.get_header_value(auth_key);
    auto pos = s.find(' ');
    if (pos != std::string::npos) {
      auto type = s.substr(0, pos);
      if (type == "Basic") {
        return false;
      } else if (type == "Digest") {
        s = s.substr(pos + 1);
        auto beg = std::sregex_iterator(s.begin(), s.end(), re);
        for (auto i = beg; i != std::sregex_iterator(); ++i) {
          auto m = *i;
          auto key = s.substr(static_cast<size_t>(m.position(1)),
                              static_cast<size_t>(m.length(1)));
          auto val = m.length(2) > 0
                         ? s.substr(static_cast<size_t>(m.position(2)),
                                    static_cast<size_t>(m.length(2)))
                         : s.substr(static_cast<size_t>(m.position(3)),
                                    static_cast<size_t>(m.length(3)));
          auth[key] = val;
        }
        return true;
      }
    }
  }
  return false;
}

// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c/440240#answer-440240
inline std::string random_string(size_t length) {
  auto randchar = []() -> char {
    const char charset[] = "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[static_cast<size_t>(rand()) % max_index];
  };
  std::string str(length, 0);
  std::generate_n(str.begin(), length, randchar);
  return str;
}

// Request implementation
inline bool Request::has_header(const char *key) const {
  return detail::has_header(headers, key);
}

inline std::string Request::get_header_value(const char *key, size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

inline size_t Request::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

inline void Request::set_header(const char *key, const char *val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val)) {
    headers.emplace(key, val);
  }
}

inline void Request::set_header(const char *key, const std::string &val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str())) {
    headers.emplace(key, val);
  }
}

inline bool Request::has_param(const char *key) const {
  return params.find(key) != params.end();
}

inline std::string Request::get_param_value(const char *key, size_t id) const {
  auto rng = params.equal_range(key);
  auto it = rng.first;
  std::advance(it, static_cast<ssize_t>(id));
  if (it != rng.second) { return it->second; }
  return std::string();
}

inline size_t Request::get_param_value_count(const char *key) const {
  auto r = params.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

inline bool Request::is_multipart_form_data() const {
  const auto &content_type = get_header_value("Content-Type");
  return !content_type.find("multipart/form-data");
}

inline bool Request::has_file(const char *key) const {
  return files.find(key) != files.end();
}

inline MultipartFormData Request::get_file_value(const char *key) const {
  auto it = files.find(key);
  if (it != files.end()) { return it->second; }
  return MultipartFormData();
}

// Response implementation
inline bool Response::has_header(const char *key) const {
  return headers.find(key) != headers.end();
}

inline std::string Response::get_header_value(const char *key,
                                              size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

inline size_t Response::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

inline void Response::set_header(const char *key, const char *val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val)) {
    headers.emplace(key, val);
  }
}

inline void Response::set_header(const char *key, const std::string &val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str())) {
    headers.emplace(key, val);
  }
}

inline void Response::set_redirect(const char *url, int stat) {
  if (!detail::has_crlf(url)) {
    set_header("Location", url);
    if (300 <= stat && stat < 400) {
      this->status = stat;
    } else {
      this->status = 302;
    }
  }
}

inline void Response::set_content(const char *s, size_t n,
                                  const char *content_type) {
  body.assign(s, n);
  set_header("Content-Type", content_type);
}

inline void Response::set_content(std::string s, const char *content_type) {
  body = std::move(s);
  set_header("Content-Type", content_type);
}

inline void
Response::set_content_provider(size_t in_length, ContentProvider provider,
                               std::function<void()> resource_releaser) {
  assert(in_length > 0);
  content_length_ = in_length;
  content_provider_ = [provider](size_t offset, size_t length, DataSink &sink) {
    return provider(offset, length, sink);
  };
  content_provider_resource_releaser_ = resource_releaser;
}

inline void Response::set_chunked_content_provider(
    ChunkedContentProvider provider, std::function<void()> resource_releaser) {
  content_length_ = 0;
  content_provider_ = [provider](size_t offset, size_t, DataSink &sink) {
    return provider(offset, sink);
  };
  content_provider_resource_releaser_ = resource_releaser;
}

// Rstream implementation
inline ssize_t Stream::write(const char *ptr) {
  return write(ptr, strlen(ptr));
}

inline ssize_t Stream::write(const std::string &s) {
  return write(s.data(), s.size());
}

template <typename... Args>
inline ssize_t Stream::write_format(const char *fmt, const Args &... args) {
  std::array<char, 2048> buf;

#if defined(_MSC_VER) && _MSC_VER < 1900
  auto sn = _snprintf_s(buf, bufsiz, buf.size() - 1, fmt, args...);
#else
  auto sn = snprintf(buf.data(), buf.size() - 1, fmt, args...);
#endif
  if (sn <= 0) { return sn; }

  auto n = static_cast<size_t>(sn);

  if (n >= buf.size() - 1) {
    std::vector<char> glowable_buf(buf.size());

    while (n >= glowable_buf.size() - 1) {
      glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
      n = static_cast<size_t>(_snprintf_s(&glowable_buf[0], glowable_buf.size(),
                                          glowable_buf.size() - 1, fmt,
                                          args...));
#else
      n = static_cast<size_t>(
          snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...));
#endif
    }
    return write(&glowable_buf[0], n);
  } else {
    return write(buf.data(), n);
  }
}

namespace detail {

// Socket stream implementation
inline SocketStream::SocketStream(socket_t sock, time_t read_timeout_sec,
                                  time_t read_timeout_usec,
                                  time_t write_timeout_sec,
                                  time_t write_timeout_usec)
    : sock_(sock), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec),
      write_timeout_sec_(write_timeout_sec),
      write_timeout_usec_(write_timeout_usec) {}

inline SocketStream::~SocketStream() {}

inline bool SocketStream::is_readable() const {
  return select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

inline bool SocketStream::is_writable() const {
  return select_write(sock_, write_timeout_sec_, write_timeout_usec_) > 0;
}

inline ssize_t SocketStream::read(char *ptr, size_t size) {
  if (!is_readable()) { return -1; }

#ifdef _WIN32
  if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    return -1;
  }
  return recv(sock_, ptr, static_cast<int>(size), 0);
#else
  return handle_EINTR([&]() { return recv(sock_, ptr, size, 0); });
#endif
}

inline ssize_t SocketStream::write(const char *ptr, size_t size) {
  if (!is_writable()) { return -1; }

#ifdef _WIN32
  if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    return -1;
  }
  return send(sock_, ptr, static_cast<int>(size), 0);
#else
  return handle_EINTR([&]() { return send(sock_, ptr, size, 0); });
#endif
}

inline void SocketStream::get_remote_ip_and_port(std::string &ip,
                                                 int &port) const {
  return detail::get_remote_ip_and_port(sock_, ip, port);
}

// Buffer stream implementation
inline bool BufferStream::is_readable() const { return true; }

inline bool BufferStream::is_writable() const { return true; }

inline ssize_t BufferStream::read(char *ptr, size_t size) {
#if defined(_MSC_VER) && _MSC_VER < 1900
  auto len_read = buffer._Copy_s(ptr, size, size, position);
#else
  auto len_read = buffer.copy(ptr, size, position);
#endif
  position += static_cast<size_t>(len_read);
  return static_cast<ssize_t>(len_read);
}

inline ssize_t BufferStream::write(const char *ptr, size_t size) {
  buffer.append(ptr, size);
  return static_cast<ssize_t>(size);
}

inline void BufferStream::get_remote_ip_and_port(std::string & /*ip*/,
                                                 int & /*port*/) const {}

inline const std::string &BufferStream::get_buffer() const { return buffer; }

} // namespace detail

// HTTP client implementation
inline Client::Client(const std::string &host)
    : Client(host, 80, std::string(), std::string()) {}

inline Client::Client(const std::string &host, int port)
    : Client(host, port, std::string(), std::string()) {}

inline Client::Client(const std::string &host, int port,
                      const std::string &client_cert_path,
                      const std::string &client_key_path)
    : host_(host), port_(port),
      host_and_port_(host_ + ":" + std::to_string(port_)),
      client_cert_path_(client_cert_path), client_key_path_(client_key_path) {}

inline Client::~Client() { stop(); }

inline bool Client::is_valid() const { return true; }

inline socket_t Client::create_client_socket() const {
  if (!proxy_host_.empty()) {
    return detail::create_client_socket(
        proxy_host_.c_str(), proxy_port_, tcp_nodelay_, socket_options_,
        connection_timeout_sec_, connection_timeout_usec_, interface_);
  }
  return detail::create_client_socket(host_.c_str(), port_, tcp_nodelay_,
                                      socket_options_, connection_timeout_sec_,
                                      connection_timeout_usec_, interface_);
}

inline bool Client::create_and_connect_socket(Socket &socket) {
  auto sock = create_client_socket();
  if (sock == INVALID_SOCKET) { return false; }
  socket.sock = sock;
  return true;
}

inline void Client::close_socket(Socket &socket, bool /*process_socket_ret*/) {
  detail::close_socket(socket.sock);
  socket_.sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  socket_.ssl = nullptr;
#endif
}

inline bool Client::read_response_line(Stream &strm, Response &res) {
  std::array<char, 2048> buf;

  detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

  if (!line_reader.getline()) { return false; }

  const static std::regex re("(HTTP/1\\.[01]) (\\d+?) .*\r\n");

  std::cmatch m;
  if (std::regex_match(line_reader.ptr(), m, re)) {
    res.version = std::string(m[1]);
    res.status = std::stoi(std::string(m[2]));
  }

  return true;
}

inline bool Client::send(const Request &req, Response &res) {
  std::lock_guard<std::recursive_mutex> request_mutex_guard(request_mutex_);

  {
    std::lock_guard<std::mutex> guard(socket_mutex_);

    auto is_alive = false;
    if (socket_.is_open()) {
      is_alive = detail::select_write(socket_.sock, 0, 0) > 0;
      if (!is_alive) { close_socket(socket_, false); }
    }

    if (!is_alive) {
      if (!create_and_connect_socket(socket_)) { return false; }

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

        if (!scli.initialize_ssl(socket_)) { return false; }
      }
#endif
    }
  }

  auto close_connection = !keep_alive_;

  auto ret = process_socket(socket_, [&](Stream &strm) {
    return handle_request(strm, req, res, close_connection);
  });

  if (close_connection) { stop(); }

  return ret;
}

inline bool Client::handle_request(Stream &strm, const Request &req,
                                   Response &res, bool close_connection) {
  if (req.path.empty()) { return false; }

  bool ret;

  if (!is_ssl() && !proxy_host_.empty()) {
    auto req2 = req;
    req2.path = "http://" + host_and_port_ + req.path;
    ret = process_request(strm, req2, res, close_connection);
  } else {
    ret = process_request(strm, req, res, close_connection);
  }

  if (!ret) { return false; }

  if (300 < res.status && res.status < 400 && follow_location_) {
    ret = redirect(req, res);
  }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  if ((res.status == 401 || res.status == 407) &&
      req.authorization_count_ < 5) {
    auto is_proxy = res.status == 407;
    const auto &username =
        is_proxy ? proxy_digest_auth_username_ : digest_auth_username_;
    const auto &password =
        is_proxy ? proxy_digest_auth_password_ : digest_auth_password_;

    if (!username.empty() && !password.empty()) {
      std::map<std::string, std::string> auth;
      if (parse_www_authenticate(res, auth, is_proxy)) {
        Request new_req = req;
        new_req.authorization_count_ += 1;
        auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
        new_req.headers.erase(key);
        new_req.headers.insert(make_digest_authentication_header(
            req, auth, new_req.authorization_count_, random_string(10),
            username, password, is_proxy));

        Response new_res;

        ret = send(new_req, new_res);
        if (ret) { res = new_res; }
      }
    }
  }
#endif

  return ret;
}

inline bool Client::redirect(const Request &req, Response &res) {
  if (req.redirect_count == 0) { return false; }

  auto location = res.get_header_value("location");
  if (location.empty()) { return false; }

  const static std::regex re(
      R"(^(?:(https?):)?(?://([^:/?#]*)(?::(\d+))?)?([^?#]*(?:\?[^#]*)?)(?:#.*)?)");

  std::smatch m;
  if (!std::regex_match(location, m, re)) { return false; }

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

  if (next_scheme.empty()) { next_scheme = scheme; }
  if (next_host.empty()) { next_host = host_; }
  if (next_path.empty()) { next_path = "/"; }

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

inline bool Client::write_request(Stream &strm, const Request &req,
                                  bool close_connection) {
  detail::BufferStream bstrm;

  // Request line
  const auto &path = detail::encode_url(req.path);

  bstrm.write_format("%s %s HTTP/1.1\r\n", req.method.c_str(), path.c_str());

  // Additonal headers
  Headers headers;
  if (close_connection) { headers.emplace("Connection", "close"); }

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

  if (!req.has_header("Accept")) { headers.emplace("Accept", "*/*"); }

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
    headers.insert(make_basic_authentication_header(
        basic_auth_username_, basic_auth_password_, false));
  }

  if (!proxy_basic_auth_username_.empty() &&
      !proxy_basic_auth_password_.empty()) {
    headers.insert(make_basic_authentication_header(
        proxy_basic_auth_username_, proxy_basic_auth_password_, true));
  }

  detail::write_headers(bstrm, req, headers);

  // Flush buffer
  auto &data = bstrm.get_buffer();
  if (!detail::write_data(strm, data.data(), data.size())) { return false; }

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
        if (!ok) { return false; }
      }
    }
  } else {
    return detail::write_data(strm, req.body.data(), req.body.size());
  }

  return true;
}

inline std::shared_ptr<Response> Client::send_with_content_provider(
    const char *method, const char *path, const Headers &headers,
    const std::string &body, size_t content_length,
    ContentProvider content_provider, const char *content_type) {
  Request req;
  req.method = method;
  req.headers = headers;
  req.path = path;

  if (content_type) { req.headers.emplace("Content-Type", content_type); }

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

    if (!detail::compress(req.body)) { return nullptr; }
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

inline bool Client::process_request(Stream &strm, const Request &req,
                                    Response &res, bool close_connection) {
  // Send request
  if (!write_request(strm, req, close_connection)) { return false; }

  // Receive response and headers
  if (!read_response_line(strm, res) ||
      !detail::read_headers(strm, res.headers)) {
    return false;
  }

  if (req.response_handler) {
    if (!req.response_handler(res)) { return false; }
  }

  // Body
  if (req.method != "HEAD" && req.method != "CONNECT") {
    auto out =
        req.content_receiver
            ? static_cast<ContentReceiver>([&](const char *buf, size_t n) {
                return req.content_receiver(buf, n);
              })
            : static_cast<ContentReceiver>([&](const char *buf, size_t n) {
                if (res.body.size() + n > res.body.max_size()) { return false; }
                res.body.append(buf, n);
                return true;
              });

    int dummy_status;
    if (!detail::read_content(strm, res, (std::numeric_limits<size_t>::max)(),
                              dummy_status, req.progress, out, decompress_)) {
      return false;
    }
  }

  if (res.get_header_value("Connection") == "close" ||
      res.version == "HTTP/1.0") {
    stop();
  }

  // Log
  if (logger_) { logger_(req, res); }

  return true;
}

inline bool Client::process_socket(Socket &socket,
                                   std::function<bool(Stream &strm)> callback) {
  return detail::process_client_socket(socket.sock, read_timeout_sec_,
                                       read_timeout_usec_, write_timeout_sec_,
                                       write_timeout_usec_, callback);
}

inline bool Client::is_ssl() const { return false; }

inline std::shared_ptr<Response> Client::Get(const char *path) {
  return Get(path, Headers(), Progress());
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             Progress progress) {
  return Get(path, Headers(), std::move(progress));
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             const Headers &headers) {
  return Get(path, headers, Progress());
}

inline std::shared_ptr<Response>
Client::Get(const char *path, const Headers &headers, Progress progress) {
  Request req;
  req.method = "GET";
  req.path = path;
  req.headers = headers;
  req.progress = std::move(progress);

  auto res = std::make_shared<Response>();
  return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             ContentReceiver content_receiver) {
  return Get(path, Headers(), nullptr, std::move(content_receiver), Progress());
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             ContentReceiver content_receiver,
                                             Progress progress) {
  return Get(path, Headers(), nullptr, std::move(content_receiver),
             std::move(progress));
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             const Headers &headers,
                                             ContentReceiver content_receiver) {
  return Get(path, headers, nullptr, std::move(content_receiver), Progress());
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             const Headers &headers,
                                             ContentReceiver content_receiver,
                                             Progress progress) {
  return Get(path, headers, nullptr, std::move(content_receiver),
             std::move(progress));
}

inline std::shared_ptr<Response> Client::Get(const char *path,
                                             const Headers &headers,
                                             ResponseHandler response_handler,
                                             ContentReceiver content_receiver) {
  return Get(path, headers, std::move(response_handler), content_receiver,
             Progress());
}

inline std::shared_ptr<Response> Client::Get(const char *path,
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

inline std::shared_ptr<Response> Client::Head(const char *path) {
  return Head(path, Headers());
}

inline std::shared_ptr<Response> Client::Head(const char *path,
                                              const Headers &headers) {
  Request req;
  req.method = "HEAD";
  req.headers = headers;
  req.path = path;

  auto res = std::make_shared<Response>();

  return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::Post(const char *path) {
  return Post(path, std::string(), nullptr);
}

inline std::shared_ptr<Response> Client::Post(const char *path,
                                              const std::string &body,
                                              const char *content_type) {
  return Post(path, Headers(), body, content_type);
}

inline std::shared_ptr<Response> Client::Post(const char *path,
                                              const Headers &headers,
                                              const std::string &body,
                                              const char *content_type) {
  return send_with_content_provider("POST", path, headers, body, 0, nullptr,
                                    content_type);
}

inline std::shared_ptr<Response> Client::Post(const char *path,
                                              const Params &params) {
  return Post(path, Headers(), params);
}

inline std::shared_ptr<Response> Client::Post(const char *path,
                                              size_t content_length,
                                              ContentProvider content_provider,
                                              const char *content_type) {
  return Post(path, Headers(), content_length, content_provider, content_type);
}

inline std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers, size_t content_length,
             ContentProvider content_provider, const char *content_type) {
  return send_with_content_provider("POST", path, headers, std::string(),
                                    content_length, content_provider,
                                    content_type);
}

inline std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers, const Params &params) {
  auto query = detail::params_to_query_str(params);
  return Post(path, headers, query, "application/x-www-form-urlencoded");
}

inline std::shared_ptr<Response>
Client::Post(const char *path, const MultipartFormDataItems &items) {
  return Post(path, Headers(), items);
}

inline std::shared_ptr<Response>
Client::Post(const char *path, const Headers &headers,
             const MultipartFormDataItems &items) {
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

inline std::shared_ptr<Response> Client::Put(const char *path) {
  return Put(path, std::string(), nullptr);
}

inline std::shared_ptr<Response> Client::Put(const char *path,
                                             const std::string &body,
                                             const char *content_type) {
  return Put(path, Headers(), body, content_type);
}

inline std::shared_ptr<Response> Client::Put(const char *path,
                                             const Headers &headers,
                                             const std::string &body,
                                             const char *content_type) {
  return send_with_content_provider("PUT", path, headers, body, 0, nullptr,
                                    content_type);
}

inline std::shared_ptr<Response> Client::Put(const char *path,
                                             size_t content_length,
                                             ContentProvider content_provider,
                                             const char *content_type) {
  return Put(path, Headers(), content_length, content_provider, content_type);
}

inline std::shared_ptr<Response>
Client::Put(const char *path, const Headers &headers, size_t content_length,
            ContentProvider content_provider, const char *content_type) {
  return send_with_content_provider("PUT", path, headers, std::string(),
                                    content_length, content_provider,
                                    content_type);
}

inline std::shared_ptr<Response> Client::Put(const char *path,
                                             const Params &params) {
  return Put(path, Headers(), params);
}

inline std::shared_ptr<Response>
Client::Put(const char *path, const Headers &headers, const Params &params) {
  auto query = detail::params_to_query_str(params);
  return Put(path, headers, query, "application/x-www-form-urlencoded");
}

inline std::shared_ptr<Response> Client::Patch(const char *path,
                                               const std::string &body,
                                               const char *content_type) {
  return Patch(path, Headers(), body, content_type);
}

inline std::shared_ptr<Response> Client::Patch(const char *path,
                                               const Headers &headers,
                                               const std::string &body,
                                               const char *content_type) {
  return send_with_content_provider("PATCH", path, headers, body, 0, nullptr,
                                    content_type);
}

inline std::shared_ptr<Response> Client::Patch(const char *path,
                                               size_t content_length,
                                               ContentProvider content_provider,
                                               const char *content_type) {
  return Patch(path, Headers(), content_length, content_provider, content_type);
}

inline std::shared_ptr<Response>
Client::Patch(const char *path, const Headers &headers, size_t content_length,
              ContentProvider content_provider, const char *content_type) {
  return send_with_content_provider("PATCH", path, headers, std::string(),
                                    content_length, content_provider,
                                    content_type);
}

inline std::shared_ptr<Response> Client::Delete(const char *path) {
  return Delete(path, Headers(), std::string(), nullptr);
}

inline std::shared_ptr<Response> Client::Delete(const char *path,
                                                const std::string &body,
                                                const char *content_type) {
  return Delete(path, Headers(), body, content_type);
}

inline std::shared_ptr<Response> Client::Delete(const char *path,
                                                const Headers &headers) {
  return Delete(path, headers, std::string(), nullptr);
}

inline std::shared_ptr<Response> Client::Delete(const char *path,
                                                const Headers &headers,
                                                const std::string &body,
                                                const char *content_type) {
  Request req;
  req.method = "DELETE";
  req.headers = headers;
  req.path = path;

  if (content_type) { req.headers.emplace("Content-Type", content_type); }
  req.body = body;

  auto res = std::make_shared<Response>();

  return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::Options(const char *path) {
  return Options(path, Headers());
}

inline std::shared_ptr<Response> Client::Options(const char *path,
                                                 const Headers &headers) {
  Request req;
  req.method = "OPTIONS";
  req.path = path;
  req.headers = headers;

  auto res = std::make_shared<Response>();

  return send(req, *res) ? res : nullptr;
}

inline size_t Client::is_socket_open() const {
  std::lock_guard<std::mutex> guard(socket_mutex_);
  return socket_.is_open();
}

inline void Client::stop() {
  std::lock_guard<std::mutex> guard(socket_mutex_);
  if (socket_.is_open()) {
    detail::shutdown_socket(socket_.sock);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    close_socket(socket_, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

inline void Client::set_timeout_sec(time_t timeout_sec) {
  set_connection_timeout(timeout_sec, 0);
}

inline void Client::set_connection_timeout(time_t sec, time_t usec) {
  connection_timeout_sec_ = sec;
  connection_timeout_usec_ = usec;
}

inline void Client::set_read_timeout(time_t sec, time_t usec) {
  read_timeout_sec_ = sec;
  read_timeout_usec_ = usec;
}

inline void Client::set_write_timeout(time_t sec, time_t usec) {
  write_timeout_sec_ = sec;
  write_timeout_usec_ = usec;
}

inline void Client::set_basic_auth(const char *username, const char *password) {
  basic_auth_username_ = username;
  basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_digest_auth(const char *username,
                                    const char *password) {
  digest_auth_username_ = username;
  digest_auth_password_ = password;
}
#endif

inline void Client::set_keep_alive(bool on) { keep_alive_ = on; }

inline void Client::set_follow_location(bool on) { follow_location_ = on; }

inline void Client::set_tcp_nodelay(bool on) { tcp_nodelay_ = on; }

inline void Client::set_socket_options(SocketOptions socket_options) {
  socket_options_ = socket_options;
}

inline void Client::set_compress(bool on) { compress_ = on; }

inline void Client::set_decompress(bool on) { decompress_ = on; }

inline void Client::set_interface(const char *intf) { interface_ = intf; }

inline void Client::set_proxy(const char *host, int port) {
  proxy_host_ = host;
  proxy_port_ = port;
}

inline void Client::set_proxy_basic_auth(const char *username,
                                         const char *password) {
  proxy_basic_auth_username_ = username;
  proxy_basic_auth_password_ = password;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_proxy_digest_auth(const char *username,
                                          const char *password) {
  proxy_digest_auth_username_ = username;
  proxy_digest_auth_password_ = password;
}
#endif

inline void Client::set_logger(Logger logger) { logger_ = std::move(logger); }

/*
 * SSL Implementation
 */
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
namespace detail {

template <typename U, typename V>
inline SSL *ssl_new(socket_t sock, SSL_CTX *ctx, std::mutex &ctx_mutex,
                    U SSL_connect_or_accept, V setup) {
  SSL *ssl = nullptr;
  {
    std::lock_guard<std::mutex> guard(ctx_mutex);
    ssl = SSL_new(ctx);
  }

  if (ssl) {
    auto bio = BIO_new_socket(static_cast<int>(sock), BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    if (!setup(ssl) || SSL_connect_or_accept(ssl) != 1) {
      SSL_shutdown(ssl);
      {
        std::lock_guard<std::mutex> guard(ctx_mutex);
        SSL_free(ssl);
      }
      return nullptr;
    }
  }

  return ssl;
}

inline void ssl_delete(std::mutex &ctx_mutex, SSL *ssl,
                       bool process_socket_ret) {
  if (process_socket_ret) {
    SSL_shutdown(ssl); // shutdown only if not already closed by remote
  }

  std::lock_guard<std::mutex> guard(ctx_mutex);
  SSL_free(ssl);
}

template <typename T>
inline bool
process_client_socket_ssl(SSL *ssl, socket_t sock, time_t read_timeout_sec,
                          time_t read_timeout_usec, time_t write_timeout_sec,
                          time_t write_timeout_usec, T callback) {
  SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec,
                       write_timeout_sec, write_timeout_usec);
  return callback(strm);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static std::shared_ptr<std::vector<std::mutex>> openSSL_locks_;

class SSLThreadLocks {
public:
  SSLThreadLocks() {
    openSSL_locks_ =
        std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());
    CRYPTO_set_locking_callback(locking_callback);
  }

  ~SSLThreadLocks() { CRYPTO_set_locking_callback(nullptr); }

private:
  static void locking_callback(int mode, int type, const char * /*file*/,
                               int /*line*/) {
    auto &lk = (*openSSL_locks_)[static_cast<size_t>(type)];
    if (mode & CRYPTO_LOCK) {
      lk.lock();
    } else {
      lk.unlock();
    }
  }
};

#endif

class SSLInit {
public:
  SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    SSL_load_error_strings();
    SSL_library_init();
#else
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
  }

  ~SSLInit() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    ERR_free_strings();
#endif
  }

private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSLThreadLocks thread_init_;
#endif
};

// SSL socket stream implementation
inline SSLSocketStream::SSLSocketStream(socket_t sock, SSL *ssl,
                                        time_t read_timeout_sec,
                                        time_t read_timeout_usec,
                                        time_t write_timeout_sec,
                                        time_t write_timeout_usec)
    : sock_(sock), ssl_(ssl), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec),
      write_timeout_sec_(write_timeout_sec),
      write_timeout_usec_(write_timeout_usec) {}

inline SSLSocketStream::~SSLSocketStream() {}

inline bool SSLSocketStream::is_readable() const {
  return detail::select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

inline bool SSLSocketStream::is_writable() const {
  return detail::select_write(sock_, write_timeout_sec_, write_timeout_usec_) >
         0;
}

inline ssize_t SSLSocketStream::read(char *ptr, size_t size) {
  if (SSL_pending(ssl_) > 0 || is_readable()) {
    return SSL_read(ssl_, ptr, static_cast<int>(size));
  }
  return -1;
}

inline ssize_t SSLSocketStream::write(const char *ptr, size_t size) {
  if (is_writable()) { return SSL_write(ssl_, ptr, static_cast<int>(size)); }
  return -1;
}

inline void SSLSocketStream::get_remote_ip_and_port(std::string &ip,
                                                    int &port) const {
  detail::get_remote_ip_and_port(sock_, ip, port);
}

static SSLInit sslinit_;

} // namespace detail

class SSLClient : public Client {
public:
  explicit SSLClient(const std::string &host);

  explicit SSLClient(const std::string &host, int port);

  explicit SSLClient(const std::string &host, int port,
                     const std::string &client_cert_path,
                     const std::string &client_key_path);

  explicit SSLClient(const std::string &host, int port, X509 *client_cert,
                     EVP_PKEY *client_key);

  ~SSLClient() override;

  bool is_valid() const override;

  void set_ca_cert_path(const char *ca_cert_file_path,
                        const char *ca_cert_dir_path = nullptr);

  void set_ca_cert_store(X509_STORE *ca_cert_store);

  void enable_server_certificate_verification(bool enabled);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const;

private:
  bool create_and_connect_socket(Socket &socket) override;
  void close_socket(Socket &socket, bool process_socket_ret) override;

  bool process_socket(Socket &socket,
                      std::function<bool(Stream &strm)> callback) override;
  bool is_ssl() const override;

  bool connect_with_proxy(Socket &sock, Response &res, bool &success);
  bool initialize_ssl(Socket &socket);

  bool verify_host(X509 *server_cert) const;
  bool verify_host_with_subject_alt_name(X509 *server_cert) const;
  bool verify_host_with_common_name(X509 *server_cert) const;
  bool check_host_name(const char *pattern, size_t pattern_len) const;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
  std::vector<std::string> host_components_;

  std::string ca_cert_file_path_;
  std::string ca_cert_dir_path_;
  X509_STORE *ca_cert_store_ = nullptr;
  bool server_certificate_verification_ = false;
  long verify_result_ = 0;

  friend class Client;
};

// SSL HTTP client implementation
inline SSLClient::SSLClient(const std::string &host)
    : SSLClient(host, 443, std::string(), std::string()) {}

inline SSLClient::SSLClient(const std::string &host, int port)
    : SSLClient(host, port, std::string(), std::string()) {}

inline SSLClient::SSLClient(const std::string &host, int port,
                            const std::string &client_cert_path,
                            const std::string &client_key_path)
    : Client(host, port, client_cert_path, client_key_path) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
                [&](const char *b, const char *e) {
                  host_components_.emplace_back(std::string(b, e));
                });
  if (!client_cert_path.empty() && !client_key_path.empty()) {
    if (SSL_CTX_use_certificate_file(ctx_, client_cert_path.c_str(),
                                     SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, client_key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

inline SSLClient::SSLClient(const std::string &host, int port,
                            X509 *client_cert, EVP_PKEY *client_key)
    : Client(host, port) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
                [&](const char *b, const char *e) {
                  host_components_.emplace_back(std::string(b, e));
                });
  if (client_cert != nullptr && client_key != nullptr) {
    if (SSL_CTX_use_certificate(ctx_, client_cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, client_key) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

inline SSLClient::~SSLClient() {
  if (ctx_) { SSL_CTX_free(ctx_); }
}

inline bool SSLClient::is_valid() const { return ctx_; }

inline void SSLClient::set_ca_cert_path(const char *ca_cert_file_path,
                                        const char *ca_cert_dir_path) {
  if (ca_cert_file_path) { ca_cert_file_path_ = ca_cert_file_path; }
  if (ca_cert_dir_path) { ca_cert_dir_path_ = ca_cert_dir_path; }
}

inline void SSLClient::set_ca_cert_store(X509_STORE *ca_cert_store) {
  if (ca_cert_store) { ca_cert_store_ = ca_cert_store; }
}

inline void SSLClient::enable_server_certificate_verification(bool enabled) {
  server_certificate_verification_ = enabled;
}

inline long SSLClient::get_openssl_verify_result() const {
  return verify_result_;
}

inline SSL_CTX *SSLClient::ssl_context() const { return ctx_; }

inline bool SSLClient::create_and_connect_socket(Socket &socket) {
  return is_valid() && Client::create_and_connect_socket(socket);
}

inline bool SSLClient::connect_with_proxy(Socket &socket, Response &res,
                                          bool &success) {
  success = true;
  Response res2;

  if (!detail::process_client_socket(
          socket.sock, read_timeout_sec_, read_timeout_usec_,
          write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
            Request req2;
            req2.method = "CONNECT";
            req2.path = host_and_port_;
            return process_request(strm, req2, res2, false);
          })) {
    close_socket(socket, true);
    success = false;
    return false;
  }

  if (res2.status == 407) {
    if (!proxy_digest_auth_username_.empty() &&
        !proxy_digest_auth_password_.empty()) {
      std::map<std::string, std::string> auth;
      if (parse_www_authenticate(res2, auth, true)) {
        Response res3;
        if (!detail::process_client_socket(
                socket.sock, read_timeout_sec_, read_timeout_usec_,
                write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
                  Request req3;
                  req3.method = "CONNECT";
                  req3.path = host_and_port_;
                  req3.headers.insert(make_digest_authentication_header(
                      req3, auth, 1, random_string(10),
                      proxy_digest_auth_username_, proxy_digest_auth_password_,
                      true));
                  return process_request(strm, req3, res3, false);
                })) {
          close_socket(socket, true);
          success = false;
          return false;
        }
      }
    } else {
      res = res2;
      return false;
    }
  }

  return true;
}

inline bool SSLClient::initialize_ssl(Socket &socket) {
  auto ssl = detail::ssl_new(
      socket.sock, ctx_, ctx_mutex_,
      [&](SSL *ssl) {
        if (ca_cert_file_path_.empty() && ca_cert_store_ == nullptr) {
          SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        } else if (!ca_cert_file_path_.empty()) {
          if (!SSL_CTX_load_verify_locations(ctx_, ca_cert_file_path_.c_str(),
                                             nullptr)) {
            return false;
          }
          SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        } else if (ca_cert_store_ != nullptr) {
          if (SSL_CTX_get_cert_store(ctx_) != ca_cert_store_) {
            SSL_CTX_set_cert_store(ctx_, ca_cert_store_);
          }
          SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        }

        if (SSL_connect(ssl) != 1) { return false; }

        if (server_certificate_verification_) {
          verify_result_ = SSL_get_verify_result(ssl);

          if (verify_result_ != X509_V_OK) { return false; }

          auto server_cert = SSL_get_peer_certificate(ssl);

          if (server_cert == nullptr) { return false; }

          if (!verify_host(server_cert)) {
            X509_free(server_cert);
            return false;
          }
          X509_free(server_cert);
        }

        return true;
      },
      [&](SSL *ssl) {
        SSL_set_tlsext_host_name(ssl, host_.c_str());
        return true;
      });

  if (ssl) {
    socket.ssl = ssl;
    return true;
  }

  close_socket(socket, false);
  return false;
}

inline void SSLClient::close_socket(Socket &socket, bool process_socket_ret) {
  detail::close_socket(socket.sock);
  socket_.sock = INVALID_SOCKET;
  if (socket.ssl) {
    detail::ssl_delete(ctx_mutex_, socket.ssl, process_socket_ret);
    socket_.ssl = nullptr;
  }
}

inline bool
SSLClient::process_socket(Socket &socket,
                          std::function<bool(Stream &strm)> callback) {
  assert(socket.ssl);
  return detail::process_client_socket_ssl(
      socket.ssl, socket.sock, read_timeout_sec_, read_timeout_usec_,
      write_timeout_sec_, write_timeout_usec_, callback);
}

inline bool SSLClient::is_ssl() const { return true; }

inline bool SSLClient::verify_host(X509 *server_cert) const {
  /* Quote from RFC2818 section 3.1 "Server Identity"

     If a subjectAltName extension of type dNSName is present, that MUST
     be used as the identity. Otherwise, the (most specific) Common Name
     field in the Subject field of the certificate MUST be used. Although
     the use of the Common Name is existing practice, it is deprecated and
     Certification Authorities are encouraged to use the dNSName instead.

     Matching is performed using the matching rules specified by
     [RFC2459].  If more than one identity of a given type is present in
     the certificate (e.g., more than one dNSName name, a match in any one
     of the set is considered acceptable.) Names may contain the wildcard
     character * which is considered to match any single domain name
     component or component fragment. E.g., *.a.com matches foo.a.com but
     not bar.foo.a.com. f*.com matches foo.com but not bar.com.

     In some cases, the URI is specified as an IP address rather than a
     hostname. In this case, the iPAddress subjectAltName must be present
     in the certificate and must exactly match the IP in the URI.

  */
  return verify_host_with_subject_alt_name(server_cert) ||
         verify_host_with_common_name(server_cert);
}

inline bool
SSLClient::verify_host_with_subject_alt_name(X509 *server_cert) const {
  auto ret = false;

  auto type = GEN_DNS;

  struct in6_addr addr6;
  struct in_addr addr;
  size_t addr_len = 0;

#ifndef __MINGW32__
  if (inet_pton(AF_INET6, host_.c_str(), &addr6)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in6_addr);
  } else if (inet_pton(AF_INET, host_.c_str(), &addr)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in_addr);
  }
#endif

  auto alt_names = static_cast<const struct stack_st_GENERAL_NAME *>(
      X509_get_ext_d2i(server_cert, NID_subject_alt_name, nullptr, nullptr));

  if (alt_names) {
    auto dsn_matched = false;
    auto ip_mached = false;

    auto count = sk_GENERAL_NAME_num(alt_names);

    for (decltype(count) i = 0; i < count && !dsn_matched; i++) {
      auto val = sk_GENERAL_NAME_value(alt_names, i);
      if (val->type == type) {
        auto name = (const char *)ASN1_STRING_get0_data(val->d.ia5);
        auto name_len = (size_t)ASN1_STRING_length(val->d.ia5);

        if (strlen(name) == name_len) {
          switch (type) {
          case GEN_DNS: dsn_matched = check_host_name(name, name_len); break;

          case GEN_IPADD:
            if (!memcmp(&addr6, name, addr_len) ||
                !memcmp(&addr, name, addr_len)) {
              ip_mached = true;
            }
            break;
          }
        }
      }
    }

    if (dsn_matched || ip_mached) { ret = true; }
  }

  GENERAL_NAMES_free((STACK_OF(GENERAL_NAME) *)alt_names);
  return ret;
}

inline bool SSLClient::verify_host_with_common_name(X509 *server_cert) const {
  const auto subject_name = X509_get_subject_name(server_cert);

  if (subject_name != nullptr) {
    char name[BUFSIZ];
    auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
                                              name, sizeof(name));

    if (name_len != -1) {
      return check_host_name(name, static_cast<size_t>(name_len));
    }
  }

  return false;
}

inline bool SSLClient::check_host_name(const char *pattern,
                                       size_t pattern_len) const {
  if (host_.size() == pattern_len && host_ == pattern) { return true; }

  // Wildcard match
  // https://bugs.launchpad.net/ubuntu/+source/firefox-3.0/+bug/376484
  std::vector<std::string> pattern_components;
  detail::split(&pattern[0], &pattern[pattern_len], '.',
                [&](const char *b, const char *e) {
                  pattern_components.emplace_back(std::string(b, e));
                });

  if (host_components_.size() != pattern_components.size()) { return false; }

  auto itr = pattern_components.begin();
  for (const auto &h : host_components_) {
    auto &p = *itr;
    if (p != h && p != "*") {
      auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' &&
                            !p.compare(0, p.size() - 1, h));
      if (!partial_match) { return false; }
    }
    ++itr;
  }

  return true;
}
#endif

// ----------------------------------------------------------------------------

} // namespace httplib
