#pragma once
#include <string_view>
#include <nlohmann/json.hpp>



namespace research {
  bool get_crtsh_domains(const char* domain, nlohmann::json* o_data);
  void print_crtsh_domains(const nlohmann::json& data);

  void print_fofa_info(std::string_view ip);

  bool get_dnsdumpster_domain(const char* domain, nlohmann::json* o_data);
  void print_dnsdumpster(const nlohmann::json& data);

}