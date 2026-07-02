#pragma once
#include "utils.hpp"

#include <openssl/ssl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>


namespace ssl {

  struct connection {
    int sock;
    struct sockaddr_in client;
    struct ssl {
      SSL* handle;
      SSL_CTX* ctx;
    } ssl;
    
  };

  struct connection connect(const char* domain, const char* port);
  struct connection connect(const char* ip, const char* port, const char* sni);
  struct connection connect(in_addr_t addr, uint16_t port, const char* sni);

  void end_reqest(const struct connection& conn);

  bool validate_cert(SSL* ssl);

  struct ::utils::curl_memory http_request(const char* url, const char* auth = "");

  std::string rsa_sign(std::string_view info);
  std::string sha256(std::string_view str);
}