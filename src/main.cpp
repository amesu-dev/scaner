#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "ssl.hpp"
#include "utils.hpp"
#include "research.hpp"



using namespace std::string_literals;

int main(int argc, char const *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <target_domain> <target_port>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  const char* domain = argv[1];
  const char* port = argv[2];
  ssl::connection connection = ssl::connect(domain, port);

  ssl::validate_cert(connection.ssl.handle);

  std::string message = 
    "GET / HTTP/1.1\r\n"s +
    "Host: " + domain + "\r\n"
    "Connection: alive\r\n"
    "\r\n\r\n";
  
  int sent_len = SSL_write(connection.ssl.handle, message.c_str(), message.size());
  SSL_shutdown(connection.ssl.handle);
  
  if (sent_len != message.size()) {
    printf("Failed to send message with code %d %#x\n", sent_len, errno);
    exit(EXIT_FAILURE);
  }


  ssl::end_reqest(connection);
  printf("SUCCESS request\n\n");


  nlohmann::json crtsh_data {};
  bool status = research::get_crtsh_domains(domain, &crtsh_data);
  if (status) printf("Failed to parse crt.sh response!\n");


  time_t t_begin = time(nullptr);
  research::print_crtsh_domains(crtsh_data);
  time_t t_end = time(nullptr);
  printf("DNS response time: %ld seconds\n\n", t_end - t_begin);

  
  nlohmann::json dump_data {};
  status = research::get_dnsdumpster_domain(domain, &dump_data);
  if (status) printf("Failed to parse dnsdumpster response!\n");
  
  research::print_dnsdumpster(dump_data);

  printf("\n");

  std::string ip = utils::ip_to_str((sockaddr*)&connection.client);
  research::print_fofa_info(ip);

  return 0;
}
