#include "research.hpp"
#include "ssl.hpp"
#include "utils.hpp"

#include <base64/base64.h>
#include <curl/curl.h>

#include <string>
#include <sys/types.h>
#include <sys/stat.h>



using namespace std::string_literals;

struct domain_info {
  time_t cert_expires_at;
  int ip;
};

namespace research {
  void print_crtsh_domains(const nlohmann::json& data) {
    const size_t size = data.size();
    std::map<std::string, struct domain_info> domains {};

    for (size_t index = 0; index < size; index += 1) {
      if (!data[index]["common_name"].is_string() || !data[index]["name_value"].is_string()) {
        (void)fprintf(stderr, "Unable to collect %ldth record from crt.sh...\n", index);
        continue;
      }

      auto common_name = data[index]["common_name"].get<std::string>();
      auto name_value = data[index]["name_value"].get<std::string>();

      if (!domains.contains(common_name)) {
        struct tm expires_at;
        // 2026-09-25T07:44:30
        strptime(
          data[index]["not_after"].get<std::string>().c_str(),
          "%Y-%m-%dT%H:%M:%S", &expires_at
        );
        time_t ts = timegm(&expires_at);

        domains.insert({ common_name, { ts, 0 } });
      }

      size_t nl_index = -1;
      while ((nl_index = name_value.find('\n')) != std::string::npos) {
        auto domain = name_value.substr(0, nl_index);
        if (!domains.contains(domain)) {
          struct tm expires_at;
          // 2026-09-25T07:44:30
          strptime(
            data[index]["not_after"].get<std::string>().c_str(),
            "%Y-%m-%dT%H:%M:%S", &expires_at
          );
          time_t ts = timegm(&expires_at);

          domains.insert({ domain, { ts, 0 } });
        }
        name_value = name_value.substr(nl_index + 1, name_value.size() - nl_index);
      }

    }

    // Fill requests array for getaddrinfo_a
    struct gaicb* reqs[domains.size()];

    size_t req_size = 0;
    for (auto& [domain, _] : domains) {
        reqs[req_size] = (struct gaicb*)calloc(1, sizeof(struct gaicb));
        reqs[req_size]->ar_name = strdup(domain.c_str());
        req_size += 1;
    }
    
    printf("Resolving %zu domains...\n", req_size);

    int status = getaddrinfo_a(GAI_WAIT, reqs, req_size, nullptr);
    if (status != 0) {
      (void)fprintf(stderr, "Unable to resolve domains: %s\n", gai_strerror(status));
      return;
    }

    char buffer[INET_ADDRSTRLEN];
    for (size_t index = 0; index < req_size; index += 1) {
      auto res = reqs[index]->ar_result;
      
      printf("%24s : ", reqs[index]->ar_name);
      if (!res) {
        printf("N/A\n");
        continue;
      }

      char* ip = utils::ip_to_str(res->ai_addr);
      printf("%-16s  ", ip ? ip : "N/A");
      free(ip);

      
      printf("%s\n", time(nullptr) - domains.at(reqs[index]->ar_name).cert_expires_at < 0 ? "EXPIRED" : "");

      freeaddrinfo(res);
    }

    domains.clear();
  }

  bool get_crtsh_domains(const char* domain, nlohmann::json* o_data) {
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
    } else {
      time_t t_begin = time(nullptr);
      printf("Requesting crt.sh for domain '%s'...\n", domain);
      auto msg = ssl::http_request(
        ("https://crt.sh/json?q="s + domain).c_str(), NULL
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
    }

    fclose(file);
    return o_data->is_discarded();
  }

  void print_fofa_info(std::string_view ip) {
    std::string timestamp = std::to_string(time(nullptr));
    std::string base64 = base64_encode(ip, false);
    std::string url = "https://api.fofa.info/v1/search/stats?qbase64="s + base64;
    url += "&ts="s + timestamp;
    url += "&filter_type=last_year&lang=en-US";
    url += "&sign=" + ssl::rsa_sign("filter_typelast_yearlangen-USqbase64"s + base64 + "ts" + timestamp);

    struct curl_slist* headers = NULL; 
    headers = curl_slist_append(
      headers, "Authorization: eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltS"
      "TJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjo"
      "iSldUIn0.eyJpZCI6MTY5NDk4MSwibWlkIjoxMDEyMjg4OTIsInVzZXJuYW1lIjoiS"
      "GVudGFpIFZpc2l0IiwicGFyZW50X2lkIjowLCJleHAiOjE3ODM1MjA1NjF9.aMs5Dw"
      "CS4U4dNG8KBlTKEUOnyRdaHYar8FI-Fd1OwRp9zfMFgWPCOvXFi_p_GHbypcqAazC_"
      "1F87YhY0t60Jbg"
    );

    auto mem = ssl::http_request(url.c_str(), headers);
    curl_slist_free_all(headers);
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


  bool get_dnsdumpster_domain(const char* domain, nlohmann::json* o_data) {
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "X-API-Key:273896788400a7d92e05b3f11934b88fc72197fcdc9053642d66673bbf74661a");
    auto msg = ssl::http_request(
      ("https://api.dnsdumpster.com/domain/"s + domain).c_str(), headers
    );

    *o_data = nlohmann::json::parse(msg.response, nullptr, false);

    return o_data->is_discarded();
  }

  void print_dnsdumpster(const nlohmann::json& data) {
    int total_a_count = data["total_a_recs"].get<int>();
    printf(
      "DNS Dumpster\nIP records: %s (%d)\n",
      total_a_count > 50 ? "First 50" : "Full list",
      total_a_count
    );
    
    std::vector<std::string> print_arrays = {
      "a", "mx", "ns"
    };

    for (auto& record_type : print_arrays) {
      if (!data[record_type].size()) {
        printf("Not found any %s records\n", record_type.c_str());
        continue;
      }

      for (auto& record : data[record_type]) {
        std::string host = record["host"].get<std::string>();
        size_t ip_count = record["ips"].size();
        for (size_t index = 0; index < ip_count; index += 1)
          printf(
            "%-2s | %24s -> %-16s (%24s) / %s\n",
            record_type.c_str(),
            !index ? host.c_str() : "",
            record["ips"][index]["ip"].get<std::string>().c_str(),
            record["ips"][index]["ptr"].get<std::string>().c_str(),
            record["ips"][index]["country_code"].get<std::string>().c_str()
          );
      }

    }
  }
}
