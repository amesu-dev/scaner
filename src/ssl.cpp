#include "ssl.hpp"
#include "utils.hpp"

#include <base64/base64.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <curl/curl.h>

#include <malloc.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <iomanip>
#include <sstream>



using namespace std::string_literals;

namespace ssl {

  struct connection connect(const char* domain, const char* port) {
    return ssl::connect(
      utils::get_ip(domain, port), htons(atoi(port)), domain
    );
  }

  struct connection connect(const char* ip, const char* port, const char* sni) {
    return ssl::connect(
      inet_addr(ip), htons(atoi(port)), sni
    );
  }

  struct connection connect(in_addr_t addr, uint16_t port, const char* sni) {
    struct connection conn {};
    conn.client.sin_addr.s_addr = addr;
    conn.client.sin_port = port;
    conn.client.sin_family = AF_INET;

    conn.sock = socket(AF_INET, SOCK_STREAM, 0);
    int err_code = ::connect(conn.sock, (sockaddr*)&conn.client, sizeof(conn.client));
    if (err_code) {
      printf("Failed to connect with error: %#x\n", err_code);
      exit(EXIT_FAILURE);
    }

    const SSL_METHOD* meth = TLS_client_method();
    SSL_CTX* ctx = conn.ssl.ctx = SSL_CTX_new(meth);
    SSL* ssl = conn.ssl.handle = SSL_new(ctx);

    SSL_set_fd(ssl, conn.sock);
    SSL_set_connect_state(ssl);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);

    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(param, sni, 0);

    SSL_set_tlsext_host_name(ssl, sni);

    int status = SSL_do_handshake(ssl);
    if (status < 0) {
      int ret = SSL_get_error(ssl, status);
      printf("HANDSHAKE ERR: (%#x) %s\n", ret, SSL_alert_desc_string(ret));
      unsigned long code = ERR_get_error();
      char buffer[512];
      ERR_error_string_n(code, buffer, sizeof(buffer));
      printf("HANDSHAKE ERR: (%#lx) %s\n", code, buffer);
    }

    return conn;
  }

  bool validate_cert(SSL* ssl) {
    int status = SSL_get_verify_result(ssl);
    if (status < 0) {
      fprintf(
        stderr,
        "Failed to check cert with code: %d (See more X509_STORE_CTX_get_error)\n"
        "Unable to see certeficate chain\n",
        status
      );
      return 0;
    }
    
    X509* cert = SSL_get0_peer_certificate(ssl);          //! INTERNAL POINTER. MUST NOT FREE
    X509_NAME* cert_name = X509_get_subject_name(cert);   //! INTERNAL POINTER. MUST NOT FREE
    char* name = X509_NAME_oneline(cert_name, nullptr, 0);

    printf(
      "Certeficate '%s' passed validation!\n"
      "Certeficate chain:\n%s -> ",
      name, name
    );
    OPENSSL_free(name);

    stack_st_X509* chain = SSL_get0_verified_chain(ssl);
    size_t size = sk_X509_num(chain);
    for (size_t index = 0; index < size; index += 1) {
      X509* c_cert = sk_X509_value(chain, index);
      
      X509_NAME* cert_name = X509_get_issuer_name(c_cert);  //! INTERNAL POINTER. MUST NOT FREE
      char* name = X509_NAME_oneline(cert_name, nullptr, 0);

      printf("%s%s", name, index + 1 < size ? " -> " : "\n");
      OPENSSL_free(name);
    }

    return 1;
  }

  void end_reqest(const struct connection& conn) {
    char buffer[256];
    while(true) {
      int len = SSL_read(conn.ssl.handle, buffer, sizeof(buffer));
      if (len > 0) continue;

      int code = SSL_get_error(conn.ssl.handle, len);
      
      if (code == SSL_ERROR_SSL || code == SSL_ERROR_SYSCALL) {
        long err = ERR_get_error();
        long reason = ERR_GET_REASON(err);
        if (reason != SSL_R_UNEXPECTED_EOF_WHILE_READING) {
          printf("SSL ERR: %s (%d/%ld)\n", ERR_reason_error_string(err), code, reason);
          continue;
        }
      } else if (code != SSL_ERROR_ZERO_RETURN) {
        printf("SSL ERR happen: %#x (len: %#x)\n", code, len);  
        continue;
      }
      

      SSL_free(conn.ssl.handle);
      close(conn.sock);
      SSL_CTX_free(conn.ssl.ctx);
      break;
    }
  }

  struct ::utils::curl_memory http_request(const char* url, const struct ::curl_slist* headers) {
    struct ::utils::curl_memory message {0, 0};

    CURL* curl = curl_easy_init();
    if (!curl) return message;
    
    char err_buffer[CURL_ERROR_SIZE];
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_buffer);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &message);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, utils::curl_write_cb);


    CURLcode result = curl_easy_perform(curl);

    if(result != CURLE_OK) {
      size_t len = strlen(err_buffer);
      fprintf(stderr, "libcurl: (%d) ", result);
      fprintf(stderr, "%s\n", len ? err_buffer : curl_easy_strerror(result));
    }

    curl_easy_cleanup(curl);

    return message;
  }


  std::string rsa_sign(std::string_view info) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    const EVP_MD* algorithm = EVP_sha256();
    EVP_DigestInit(ctx, algorithm);

    EVP_DigestUpdate(ctx, info.data(), info.length());
    
    unsigned int hash_len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    EVP_DigestFinal(ctx, hash, &hash_len);

    FILE* file = fopen("fofa.pem", "r");
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    // fclose(file);
    
    if (!key) {
      printf("Failed to read RSA private key!\n");
      exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX* pk_ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_sign_init(pk_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pk_ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(pk_ctx, EVP_sha256());
    
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key);
    
    size_t ret_len;
    EVP_PKEY_sign(pk_ctx, nullptr, &ret_len, hash, hash_len);
    unsigned char* ret_string = (unsigned char*)calloc(ret_len, 1);
    EVP_PKEY_sign(pk_ctx, ret_string, &ret_len, hash, hash_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pk_ctx);
    EVP_PKEY_free(key);

    return base64_encode(
      std::string((char*)ret_string), false
    );
  }

  std::string sha256(std::string_view str) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    const EVP_MD* algorithm = EVP_sha256();
    if(!algorithm) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if(EVP_DigestInit(ctx, algorithm) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if(EVP_DigestUpdate(ctx, str.data(), str.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if(EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
      EVP_MD_CTX_free(ctx);
      return "";
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return std::string((char*)hash);
  }
}