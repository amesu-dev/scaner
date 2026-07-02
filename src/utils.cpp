#include "utils.hpp"
#include "ssl.hpp"

#include <base64/base64.h>

#include <malloc.h>
#include <string>
#include <map>

#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>



using namespace std::string_literals;

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

  void print_domains(const nlohmann::json& data) {
    const size_t size = data.size();
    std::map<std::string, int> domains {};
    
    size_t reqs_size = 0;
    struct gaicb* reqs[size];

    for (size_t index = 0; index < size; index += 1) {
      if (!data[index]["common_name"].is_string() || !data[index]["name_value"].is_string()) {
        (void)fprintf(stderr, "Unable to collect %ldth record from crt.sh...\n", index);
        continue;
      }

      auto common_name = data[index]["common_name"].get<std::string>();
      auto name_value = data[index]["name_value"].get<std::string>();

      domains.insert({ common_name, 0 });
      if (reqs_size != domains.size()) {
        reqs[reqs_size] = (struct gaicb*)calloc(1, sizeof(struct gaicb));
        reqs[reqs_size]->ar_name = strdup(common_name.c_str());
        reqs_size += 1;
      }

      size_t nl_index = -1;
      while ((nl_index = name_value.find('\n')) != std::string::npos) {
        auto domain = name_value.substr(0, nl_index);
        domains.insert({ domain, 0 });
        if (reqs_size != domains.size()) {
          reqs[reqs_size] = (struct gaicb*)calloc(1, sizeof(struct gaicb));
          reqs[reqs_size]->ar_name = strdup(domain.c_str());
          reqs_size += 1;
        }
        name_value = name_value.substr(nl_index + 1, name_value.size() - nl_index);
      }

    }

    domains.clear();

    printf("Resolving %zu domains...\n", reqs_size);

    int status = getaddrinfo_a(GAI_WAIT, reqs, reqs_size, nullptr);
    if (status != 0) {
      (void)fprintf(stderr, "Unable to resolve domains: %s\n", gai_strerror(status));
      return;
    }

    char buffer[INET_ADDRSTRLEN];
    for (size_t index = 0; index < reqs_size; index += 1) {
      auto res = reqs[index]->ar_result;
      
      printf("%s : ", reqs[index]->ar_name);
      if (!res) {
        printf("N/A\n");
        continue;
      }

      char* ip = ip_to_str(res->ai_addr);
      printf("%s\n", ip ? ip : "N/A");
      free(ip);
      
      freeaddrinfo(res);
    }
  }

  void get_crtsh_domains(const char* domain, nlohmann::json* o_data) {
    FILE* file = fopen(("crt-sh."s + domain + ".log").c_str(), "r+");
    struct stat file_stat {};
    fstat(fileno(file), &file_stat);
    
    //? 150 is size of Bad Gateay response from crt.sh
    if (file_stat.st_size != 150 && time(nullptr) - file_stat.st_mtim.tv_sec <= 3600 * 24) {
      printf("Using cached crt.sh response for domain '%s'...\n", domain);

      fseek(file, 0, SEEK_END);
      size_t size = ftell(file);
      fseek(file, 0, SEEK_SET);
      char* j_buffer = (char*)calloc(size + 1, sizeof(char));
      fread(j_buffer, sizeof(char), size, file);
      
      *o_data = nlohmann::json::parse(j_buffer, nullptr, false);
      if (o_data->is_discarded()) {
        printf("Failed to parse crt.sh response!\n");
        exit(EXIT_FAILURE);
      }
    } else {
      time_t t_begin = time(nullptr);
      printf("Requesting crt.sh for domain '%s'...\n", domain);
      auto msg = ssl::http_request(
        ("https://crt.sh/json?q="s + domain).c_str()
      );

      if (!msg.size) {
        printf("Failed to make curl request!\n");
        exit(EXIT_FAILURE);
      }

      time_t t_end = time(nullptr);

      printf(
        "CRT.SH INFO: (See crt-sh.%s.log)\n"
        "Response size: %zu\n"
        "Response time: %ld seconds\n\n",
        domain, msg.size, t_end - t_begin
      );

      file = freopen(("crt-sh."s + domain + ".log").c_str(), "w", file);
      fwrite(msg.response, sizeof(char), msg.size, file);

      *o_data = nlohmann::json::parse(msg.response, nullptr, false);
      if (o_data->is_discarded()) {
        printf("Failed to parse crt.sh response!\n");
        exit(EXIT_FAILURE);
      }
    }

    fclose(file);
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

  void print_fofa_info(std::string_view ip) {
    std::string timestamp = std::to_string(time(nullptr));
    std::string base64 = base64_encode(ip, false);
    std::string url = "https://api.fofa.info/v1/search/stats?qbase64="s + base64;
    url += "&ts="s + timestamp;
    url += "&filter_type=last_year&lang=en-US";
    url += "&sign=" + ssl::rsa_sign("filter_typelast_yearlangen-USqbase64"s + base64 + "ts" + timestamp);

    std::string auth = "eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltS"
      "TJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjo"
      "iSldUIn0.eyJpZCI6MTY5NDk4MSwibWlkIjoxMDEyMjg4OTIsInVzZXJuYW1lIjoiS"
      "GVudGFpIFZpc2l0IiwicGFyZW50X2lkIjowLCJleHAiOjE3ODM1MjA1NjF9.aMs5Dw"
      "CS4U4dNG8KBlTKEUOnyRdaHYar8FI-Fd1OwRp9zfMFgWPCOvXFi_p_GHbypcqAazC_"
      "1F87YhY0t60Jbg";

    auto mem = ssl::http_request(url.c_str(), auth.c_str());
    if (!mem.size) {
      printf("Failed to make curl request!\n");
      exit(EXIT_FAILURE);
    }

    nlohmann::json data = nlohmann::json::parse(mem.response, nullptr, false);
    if (data.is_discarded()) {
      printf("Failed to parse fofa.info response!\n");
      exit(EXIT_FAILURE);
    }

    printf("FOFA info found\nCountries:");
    for (const auto& country : data["data"]["countries"])
      printf(" %s(%d)", country["name"].get<std::string>().c_str(), country["count"].get<int>());
    
    if (data["data"]["ranks"]["port"].is_array() && data["data"]["ranks"]["port"].size()) {
      printf("\nOpen ports:");
      for (const auto& port : data["data"]["ranks"]["port"])
        printf(" %s(%d)", port["name"].get<std::string>().c_str(), port["count"].get<int>());
    }

    if (data["data"]["ranks"]["server"].is_array() && data["data"]["ranks"]["server"].size()) {
      printf("\nServices:");
      for (const auto& service : data["data"]["ranks"]["server"])
        printf(" %s(%d)", service["name"].get<std::string>().c_str(), service["count"].get<int>());
    }

    printf("\n");
  }
}

