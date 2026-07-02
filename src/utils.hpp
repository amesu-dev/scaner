#pragma once
#include <string.h>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>



namespace utils {
  struct curl_memory {
    char* response;
    size_t size;
  };

  size_t curl_write_cb(char *data, size_t count, size_t size, void *clientp);

  void print_domains(const nlohmann::json& data);

  void get_crtsh_domains(const char* domain, nlohmann::json* o_data);

  char* ip_to_str(const sockaddr* addr);
  in_addr_t get_ip(const char* domain, const char* port = "443");
  
  void print_fofa_info(std::string_view ip);

}

