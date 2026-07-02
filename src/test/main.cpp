#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void ssl_info_log(const SSL *ssl, int where, int ret) {
  char* cb_where_str;
  switch (where)
  {
  case SSL_CB_LOOP:
    cb_where_str = "Callback has been called to indicate state change inside a loop.";
    break;
  case SSL_CB_EXIT:
    cb_where_str = "SSL_CB_EXIT";
    break;
  case SSL_CB_ALERT:
    cb_where_str = "SSL_CB_ALERT";
    break;
  case SSL_CB_READ_ALERT:
    cb_where_str = "SSL_CB_READ_ALERT";
    break;
  case SSL_CB_WRITE_ALERT:
    cb_where_str = "SSL_CB_WRITE_ALERT";
    break;
  case SSL_CB_HANDSHAKE_START:
    cb_where_str = "SSL_CB_HANDSHAKE_START";
    break;
  case SSL_CB_HANDSHAKE_DONE:
    cb_where_str = "SSL_CB_HANDSHAKE_DONE";
    break;

  case SSL_CB_CONNECT_LOOP :
    cb_where_str = "SSL_CB_CONNECT_LOOP";
    break;
  case SSL_CB_CONNECT_EXIT :
    cb_where_str = "SSL_CB_CONNECT_EXIT";
    break;
  case SSL_CB_ACCEPT_LOOP :
    cb_where_str = "SSL_CB_ACCEPT_LOOP";
    break;
  default:
    cb_where_str = "Unknown";
  }

  printf(
    "ERR caused at '%s' with code %#x ('%s')\n",
    cb_where_str, ret, SSL_alert_desc_string(ret)
  );
}

int main(int argc, char const *argv[]) {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  sockaddr_in info = {};
  info.sin_addr.s_addr = inet_addr("147.182.252.2");
  info.sin_port = htons(443);
  info.sin_family = AF_INET;

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  int err_code = ::connect(sock, (sockaddr*)&info, sizeof(info));
  if (err_code) {
    printf("Failed to connect with error: %#x %#x\n", err_code, errno);
    exit(EXIT_FAILURE);
  }

  const SSL_METHOD* meth = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(meth);
  SSL* ssl = SSL_new(ctx);

  SSL_set_tlsext_host_name(ssl, "echo.free.beeceptor.com");

  SSL_set_info_callback(ssl, ssl_info_log);

  SSL_set_fd(ssl, sock);
  SSL_set_connect_state(ssl);
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  int status = SSL_do_handshake(ssl);
  if (status < 0) {
    int ret = SSL_get_error(ssl, status);
    printf("ERR: (%#x) %s\n", ret, SSL_alert_desc_string(ret));
    unsigned long code = ERR_get_error();
    char buffer[512];
    ERR_error_string_n(code, buffer, sizeof(buffer));
    printf("ERR: (%#lx) %s\n", code, buffer);
  }

  char message[] = "\
GET / HTTP/1.1\r\n\
Host: echo.free.beeceptor.com\r\n\
Connection: alive\r\n\
\r\n\r\n";

  int sent_len = SSL_write(ssl, message, sizeof(message));
  if (sent_len != sizeof(message)) {
    printf("Failed to send message with code %d %#x\n", sent_len, errno);
  } else printf("Message sent: %s\n", message);

  SSL_shutdown(ssl);
  char buff[1024];
  while(true) {
    int code = SSL_read(ssl, buff, sizeof(buff));
    printf("Code: %d\n", code);
    if (code <= 0 ) {
      int ret = SSL_get_error(ssl, code);
      printf("ERR codes: %#x %#lx", ret, ERR_peek_error());
      if (ret == SSL_ERROR_ZERO_RETURN) {
        printf("Read EOF\n");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        EVP_cleanup();

        break;
      }
    }
    else {
      printf("Recieved data (%zu): %s\n", code, buff);
    }

    // if (code == 5) SSL_shutdown(ssl);
  }
  
  // SSL_shutdown(ssl);
  
  return 0;
}
