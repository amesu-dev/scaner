#include "utils.hpp"
#include "ssl.hpp"

#include <malloc.h>
#include <string>
#include <map>

#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>



namespace utils {
  size_t curl_write_cb(char *data, size_t count, size_t size, void *clientp) {
    struct curl_memory* mem = (struct curl_memory*)clientp;
 
    char* ptr = (char*)realloc(mem->response, mem->size + size + 1);
    if(!ptr) return 0;  /* out of memory */
  
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, size);
    mem->size += size;
    mem->response[mem->size] = 0;
  
    return size;
  }

  in_addr_t get_ip(const char* domain, const char* port) {
    addrinfo* res = (addrinfo*)malloc(sizeof(addrinfo));
    addrinfo* hint = (addrinfo*)calloc(1, sizeof(addrinfo));
    hint->ai_socktype = SOCK_STREAM;
    hint->ai_family = AF_INET;

    getaddrinfo(domain, port, hint, &res);

    in_addr_t addr = *(in_addr_t*)(res->ai_addr->sa_data + 2);
    free(hint);
    free(res);

    return addr;
  }

  char* ip_to_str(const sockaddr* addr) {
    char* buffer = (char*)malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, addr->sa_data + 2, buffer, INET_ADDRSTRLEN);
    return buffer;
  }
}
