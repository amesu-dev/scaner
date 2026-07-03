#pragma once
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>


namespace utils {
  struct curl_memory {
    char* response;
    size_t size;
  };

  size_t curl_write_cb(char *data, size_t count, size_t size, void *clientp);

  char* ip_to_str(const sockaddr* addr);
  in_addr_t get_ip(const char* domain, const char* port = "443");
}
