#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

#include "err.h"

#define TIMEOUT 3000
#define MAX_DOMAIN_LENGTH 255
#define FAIL    -1
#define EXT_LENGTH 4
#define PORT 443

#define DNS_FAILURE FAIL
#define SOCK_FAILURE FAIL
#define BUF_SIZE 16384

#define DELIMITER "\r\n"
#define DELIMITER_LEN 2

#define DURATION 10000000
#define TRIAL 5

#define LOG_NAME "last_domain"
#define DNS_SERVER_ERROR "dns_server_error"
#define DNS_CLIENT_ERROR "dns_client_error"

int open_connection(int rank, const char *hostname, int port, unsigned char **addr);
int get_next(FILE *fp, int *rank, char *hostname);
void make_log_file(int rank, char *hostname, int version);
void clear_log_file(int err);
int is_progress();
int is_accessible(int fd, size_t msec, int flag);
int is_readable(int fd, size_t msec);
int is_writeable(int fd, size_t msec);
void enable_tls_extensions(SSL *ssl, char *hostname);
int first_tls_handshake(SSL_CTX *ctx, int rank, char *hostname, int version);
SSL_SESSION *tls_v1_3_handshake(SSL_CTX *ctx, SSL_SESSION *session, int rank, 
    char *hostname, int early);
SSL_SESSION *tls_v1_2_handshake(SSL_CTX *ctx, SSL_SESSION *session, int rank, char *hostname);
unsigned long get_current_microseconds();
void msg_callback(int write, int version, int content_type, const void *buf, size_t len, 
    SSL *ssl, void *arg);
int ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv, 
    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc);

SSL_CTX* init_client_ctx(void);
void load_ecdh_params(SSL_CTX *ctx);
FILE *fp, *perf;
unsigned char *home_directory, *date;
int complete, result, trial, maxfd = 0;
char ip[16];
static int new_session_cb(SSL *s, SSL_SESSION *sess);
BIO *bp;
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);

void make_perf_log_file(int rank, char *hostname);
void clear_perf_log_file(void);
int check_error();

char log_domain_name[20] = {0, };
char dns_server_error[20] = {0, };
char dns_client_error[20] = {0, };

int new_session = 0;

enum {
  SOCK_FLAG = 1,
  SOCK_READABLE = SOCK_FLAG,
  SOCK_WRITEABLE = SOCK_FLAG << 1
};

int usage(const char *pname)
{
  printf(">> Usage: %s [options]\n", pname);
  printf(">> Options\n");
  printf("  -l, --list    Target domain list\n");
  printf("  -h, --home    Log home directory\n");
  printf("  -s, --serial  Serial number of the process\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  FILE *domains;
  int fd;
  int rank, early;
	int i, c, e, rc, ret, state, ilen, elen, serial, timeout = TIMEOUT;
  char hostname[MAX_DOMAIN_LENGTH];
  char log_directory[MAX_DOMAIN_LENGTH] = {0, };
  unsigned char buf[11] = {0, };
  char *list, *pname;
  SSL_SESSION *session;
  SSL_CTX *ctx;
  struct timeval tv, ts;
  struct stat st = {0};
  time_t now;

  pname = argv[0];

  list = NULL;
  home_directory = NULL;
  serial = -1;
  e = ERR_NONE;
  session = NULL;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"list", required_argument, 0, 'l'},
      {"home", required_argument, 0, 'h'},
      {"serial", required_argument, 0, 's'},
      {0, 0, 0, 0}
    };

    const char *opt = "l:h:s:";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'l':
        list = optarg;
        if (access(list, F_OK) == -1)
          e |= ERR_NO_FILE_EXIST;
        break;

      case 'h':
        home_directory = optarg;
        if (stat(home_directory, &st) == -1)
        {
          if (mkdir(home_directory, 0755) < 0)
            e |= ERR_HOME_DIRECTORY_NOT_CREATED;
        }
        break;

      case 's':
        serial = atoi(optarg);
        if (serial == 0)
          e |= ERR_INVALID_SERIAL_NUMBER;
        break;

      default:
        usage(pname);
    }
  }

  if (!list)
  {
    printf("Error: Domain list file should be inserted\n");
    usage(pname);
  }

  if (!home_directory)
  {
    printf("Error: Home directory is not set\n");
    usage(pname);
  }

  if (serial < 0)
  {
    printf("Error: Serial number is not set\n");
    usage(pname);
  }

  now = time(NULL);
  strftime(buf, 256, "%Y-%m-%d", localtime(&now));
  date = buf;

  sprintf(log_directory, "%s/%s", home_directory, date);
  if (stat(log_directory, &st) == -1)
  {
    if (mkdir(log_directory, 0755) < 0)
    {
      e |= ERR_LOG_DIRECTORY_NOT_CREATED;
    }
  }

  if (e)
  {
    if (e & ERR_NO_FILE_EXIST)
      printf("Error: File %s does not exist\n", list);

    if (e & ERR_HOME_DIRECTORY_NOT_CREATED)
      printf("Error: Home directory %s does not exist\n", home_directory);

    if (e & ERR_LOG_DIRECTORY_NOT_CREATED)
      printf("Error: Log directory %s is not created\n", log_directory);

    if (e & ERR_INVALID_SERIAL_NUMBER)
      printf("Error: Serial number %d is invalid\n", serial);

    usage(pname);
  }


  bp = BIO_new_fp(stdout, BIO_NOCLOSE);

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  snprintf(log_domain_name, 20, "%s_%d", LOG_NAME, serial);
  snprintf(dns_server_error, 20, "%s_%d", DNS_SERVER_ERROR, serial);
  snprintf(dns_client_error, 20, "%s_%d", DNS_CLIENT_ERROR, serial);

  gettimeofday(&ts, NULL);
  elen = strlen(home_directory) + strlen(date) + 30;
  ilen = strlen(home_directory) + strlen(date) + 30;
  domains = fopen(list, "r");

  if (!domains)
  {
    perror("Error in opening the domain list file");
    exit(1);
  }

  while (1)
  {
    ret = get_next(domains, &rank, hostname);
    if (ret < 0)
    {
      break;
    }

    ctx = init_client_ctx();
    ret = first_tls_handshake(ctx, rank, hostname, TLS1_3_VERSION);

    if (ret == TLS1_3_VERSION)
    {
      make_perf_log_file(rank, hostname);
      sleep(0.1);

      // TLS 1.3 Full Handshake
      for (i=0; i<TRIAL; i++)
      {
        session = NULL; early = 0;
        printf("TLS 1.3 full: %d\n", i);
        session = tls_v1_3_handshake(ctx, session, rank, hostname, early);
        sleep(0.1);
      }
      
      if (session)
      {
        // TLS 1.3 Abbreviate Handshake 
        for (i=0; i<TRIAL; i++)
        {
          early = 0;
          printf("TLS 1.3 abbreviate: %d\n", i);
          session = tls_v1_3_handshake(ctx, session, rank, hostname, early);
          sleep(0.1);
        }

        // TLS 1.3 0-rtt Handshake 
        if (SSL_SESSION_get_max_early_data(session) > 0)
        {
          for (i=0; i<TRIAL; i++)
          {
            early = 1;
            printf("TLS 1.3 0-rtt: %d\n", i);
            session = tls_v1_3_handshake(ctx, session, rank, hostname, early);
            sleep(0.1);
          }
        }
      }

      ret = first_tls_handshake(ctx, rank, hostname, TLS1_2_VERSION);

      // TLS 1.2 Full Handshake
      for (i=0; i<TRIAL; i++)
      {
        session = NULL;
        printf("TLS 1.2 full: %d\n", i);
        session = tls_v1_2_handshake(ctx, session, rank, hostname);
        sleep(0.1);
      }

      // TLS 1.2 Abbreviate Handshake
      for (i=0; i<TRIAL; i++)
      {
        printf("TLS 1.2 abbreviate: %d\n", i);
        tls_v1_2_handshake(ctx, session, rank, hostname);
        sleep(0.1);
      }
      
      clear_perf_log_file();
    }
  }

err:
  if (ctx)
  {
    SSL_CTX_free(ctx);
    ctx = NULL;
  }

  if (domains)
  {
    fclose(domains);
    domains = NULL;
  }

  return 0;
}

int check_error()
{
  int ret = 0;
  switch (errno)
  {
    case ENETDOWN:
      ret = -1;
      break;
    default:
      ret = 0;
  }

  return ret;
}

int first_tls_handshake(SSL_CTX *ctx, int rank, char *hostname, int version)
{
  int fd, ret, timeout = TIMEOUT;
  SSL *ssl;
  struct timeval tv, ts;
  fd_set fds, readfds;
  unsigned char *addr;

  addr = NULL;
  ret = -1;
  fd = open_connection(rank, hostname, PORT, &addr);
  if (fd > maxfd)
    maxfd = fd;
  else if (fd == -500)
  {
    fprintf(stderr, "dns failure\n");
    ret = DNS_FAILURE;
    goto err;
  }
  else if (fd < 0)
  {
    fprintf(stderr, "socket failure\n");
    ret = SOCK_FAILURE;
    goto err;
  }

  complete = 0;
  result = 0;
  trial = 10;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
	SSL_set_msg_callback(ssl, msg_callback);
  SSL_set_max_proto_version(ssl, version);
  enable_tls_extensions(ssl, hostname);

  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  tv.tv_sec = TIMEOUT/1000;
  tv.tv_usec = 0;

  if (select(maxfd + 1, NULL, &fds, NULL, &tv) == 1)
  {
    int so_error;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

    if (so_error == 0)
    {
      make_log_file(rank, hostname, version);

      while (1)
      {
        ret = SSL_connect(ssl);

        if (ret < 0)
        {
          switch (SSL_get_error(ssl, ret))
          {
            case SSL_ERROR_WANT_READ:
              trial--;
              if (trial >= 0 && is_readable(fd, timeout))
                continue;
              break;
            case SSL_ERROR_WANT_WRITE:
              trial--;
              if (trial >= 0 && is_writeable(fd, timeout))
                continue;
              break;
            case SSL_ERROR_SYSCALL:
              trial--;
              if (trial >=0 && is_progress())
              {
                if (SSL_want_write(ssl))
                {
                  if (trial >= 0 && is_writeable(fd, timeout))
                    continue;
                }
                else if (SSL_want_read(ssl))
                {
                  if (trial >= 0 && is_readable(fd, timeout))
                    continue;
                }
              }
              else
              {
                complete = 1;
                break;
              }
            default:
              result = 1;
              complete = 2;
              break;
          }

          if (trial < 0)
            complete = 3;

          if (complete)
            break;
        }

        else if (ret == 0)
        {
          break;
        }
        else
        {
          break;
        }
      }

      if (SSL_is_init_finished(ssl))
        ret = SSL_version(ssl);
      else
        ret = -1;
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
      
      if (addr)
      {
        fprintf(fp, "IP Address: %s\n", addr);
        free(addr);
        addr = NULL;
      }
      clear_log_file(complete);
      fprintf(stderr, "\n");
      result = 1;
    }
  }
  else
  {
    result = 1;
  }

err:
  if (addr)
  {
    free(addr);
    addr = NULL;
  }
  close(fd);
  fd = -1;
  return ret;
}

int do_tls_handshake(SSL *ssl)
{
  int fd, ret, timeout = TIMEOUT;
  unsigned long base, curr;
  fd = SSL_get_fd(ssl);
  base = get_current_microseconds();
  trial = 10;

  while (1)
  {
    ret = SSL_connect(ssl);

    if (ret < 0)
    {
      switch (SSL_get_error(ssl, ret))
      {
        case SSL_ERROR_WANT_READ:
          trial--;
          if (trial >= 0 && is_readable(fd, timeout))
            continue;
          break;
        case SSL_ERROR_WANT_WRITE:
          trial--;
          if (trial >= 0 && is_writeable(fd, timeout))
            continue;
          break;
        case SSL_ERROR_SYSCALL:
          trial--;
          if (trial >=0 && is_progress())
          {
            if (SSL_want_write(ssl))
            {
              if (trial >= 0 && is_writeable(fd, timeout))
                continue;
            }
            else if (SSL_want_read(ssl))
            {
              if (trial >= 0 && is_readable(fd, timeout))
                continue;
            }
          }
          else
          {
            complete = 1;
            break;
          }
        default:
          result = 1;
          complete = 2;
          break;
      }

      if (trial < 0)
        complete = 3;

      if (complete)
        break;
    }
    else if (ret == 0)
    {
      break;
    }
    else
    {
      break;
    }
  }
  return ret;
}

SSL_SESSION *tls_v1_3_handshake(SSL_CTX *ctx, SSL_SESSION *session, int rank, 
    char *hostname, int early)
{
  char wbuf[BUF_SIZE], rbuf[BUF_SIZE];
  int fd, ret, rlen, sent, recv = -1, timeout = TIMEOUT, total = -1, offset = 0, cont = 1;
  size_t wlen;
  SSL *ssl;
  struct timeval tv, ts;
  unsigned long start, hs_end, end, base, curr;
  unsigned char *addr;
  fd_set fds, readfds;

  addr = NULL;
  fprintf(perf, "TLSv1.3 Experiment: ");
  fd = open_connection(rank, hostname, PORT, &addr);
  if (fd > maxfd)
    maxfd = fd;
  else if (fd == -500)
  {
    fprintf(perf, "DNS failure\n");
    ret = DNS_FAILURE;
    goto err;
  }
  else if (fd < 0)
  {
    fprintf(perf, "Socket failure\n");
    ret = SOCK_FAILURE;
    goto err;
  }

  memset(wbuf, 0x0, BUF_SIZE);
  memset(rbuf, 0x0, BUF_SIZE);
  complete = 0;
  result = 0;
  trial = 10;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, hostname);
  rlen = http_make_request(hostname, strlen(hostname), NULL, 0, wbuf, &rlen);
  wbuf[rlen] = 0;

  if (session)
  {
    if (SSL_SESSION_is_resumable(session))
    {
      SSL_set_session(ssl, session);
    
      if (SSL_SESSION_get_max_early_data(session) > 0)
      {
        fprintf(perf, "2\n"); // 0-RTT handshake
        cont = 1;
        while (cont && (!SSL_write_early_data(ssl, wbuf, rlen, &wlen)))
        {
          switch (SSL_get_error(ssl, 0))
          {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_ASYNC:
            case SSL_ERROR_WANT_READ:
              continue;
            default:
              fprintf(perf, "Error writing early data\n");
              cont = 0;
              break;
          }
        }
      }
      else
      {
        fprintf(perf, "1\n"); // Abbreviate handshake
      
      }
    }
    else
    {
      fprintf(perf, "3\n"); // Session is not resumable
    }

    //printf("max_early_data: %d, request length: %d, early data written: %ld\n", 
    //    SSL_SESSION_get_max_early_data(session), rlen, wlen);
  }
  else
  {
    fprintf(perf, "0\n"); // Full handshake
  }

  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  tv.tv_sec = TIMEOUT/1000;
  tv.tv_usec = 0;

  if (select(maxfd + 1, NULL, &fds, NULL, &tv) == 1)
  {
    int so_error;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

    if (so_error == 0)
    {
      start = get_current_microseconds();
      do_tls_handshake(ssl);
      hs_end = get_current_microseconds();
      
      if (!SSL_is_init_finished(ssl))
      {
        fprintf(perf, "%s Handshake: -1\n", SSL_get_version(ssl));
        fprintf(perf, "%s Total: -1\n", SSL_get_version(ssl));
        goto err;
      }

      switch (SSL_get_early_data_status(ssl))
      {
        case SSL_EARLY_DATA_REJECTED:
          //fprintf(perf, "Early data was *rejected*\n");
        case SSL_EARLY_DATA_NOT_SENT:
          fprintf(perf, "Early data: 0\n"); // Early data not used

          sent = -1;
          base = get_current_microseconds();
          while (sent < 0 && ((curr = get_current_microseconds()) < base + DURATION / 10))
          {
            sent = SSL_write(ssl, wbuf, rlen);
//            sleep(0.1);
          }

          if (sent < 0)
          {
            fprintf(perf, "%s Handshake: -1\n", SSL_get_version(ssl));
            fprintf(perf, "%s Total: -1\n", SSL_get_version(ssl));
            goto err;
          }

          base = get_current_microseconds();
          do {
            recv = SSL_read(ssl, rbuf, BUF_SIZE);
  
            if (recv > 0)
            {
              if (total <= 0)
              {
                total = http_parse_response(rbuf, recv);
              }
              offset += recv;

              if (rbuf[0] == '0')
                break;
            }
            else if (recv == 0)
              break;
            recv = -1;
          } while (total > offset && ((curr = get_current_microseconds()) < base + DURATION));
          end = get_current_microseconds();
          //rbuf[offset] = 0;
          //fprintf(perf, "Sent Data (%d bytes): %s\n", sent, wbuf);
          //fprintf(perf, "Received Data (%d bytes): %s\n", offset, rbuf);

          fprintf(perf, "%s Handshake: %.2lf ms\n", SSL_get_version(ssl), 
              (hs_end - start)/1000.0);
          fprintf(perf, "%s Total: %.2lf ms\n", SSL_get_version(ssl), 
              (end - start)/1000.0);
          // printf("\n");
          break;
        case SSL_EARLY_DATA_ACCEPTED:
          fprintf(perf, "Early data: 1\n"); // Early data used
          recv = -1;
          base = get_current_microseconds();
          while (recv < 0 && ((curr = get_current_microseconds()) < base + DURATION / 10))
          {
            recv = SSL_read(ssl, rbuf, BUF_SIZE);
//            sleep(0.1);
          }
          end = get_current_microseconds();

          if (recv > 0)
          {
            rbuf[recv] = 0;
            //fprintf(perf, "Sent Data (%ld bytes): %s\n", wlen, wbuf);
            //fprintf(perf, "Received Data (%d bytes): %s\n", recv, rbuf);
            fprintf(perf, "%s Handshake: %.2lf ms\n", SSL_get_version(ssl), 
                (hs_end - start)/1000.0);
            fprintf(perf, "%s Total: %.2lf ms\n", SSL_get_version(ssl), 
                (end - start)/1000.0);
            //printf("\n");
          }
          else
          {
            fprintf(perf, "%s Handshake: -1\n", SSL_get_version(ssl));
            fprintf(perf, "%s Total: -1\n", SSL_get_version(ssl));
          }
          break;
      }

      if (!new_session)
      {
        ret = -1;
        base = get_current_microseconds();
        memset(rbuf, 0x0, BUF_SIZE);
        new_session = 0;
        while (new_session == 0 && ((curr = get_current_microseconds()) < (base + DURATION)))
        {
          SSL_read(ssl, rbuf, BUF_SIZE);
          sleep(0.5);
        }
      }
      new_session = 0;

      session = SSL_get0_session(ssl);
      if (SSL_SESSION_is_resumable(session))
      {
        fprintf(perf, "Resumable: 1\n"); // Resumable
      }
      else
      {
        fprintf(perf, "Resumable: 0\n"); // Not resumable
      }

      fprintf(perf, "Max early data: %d\n", SSL_SESSION_get_max_early_data(session));
      //SSL_SESSION_print(bp, session);

      if (SSL_session_reused(ssl))
      {
        fprintf(perf, "Reused: 1\n"); // Reused
      }
      else
      {
        fprintf(perf, "Reused: 0\n"); // Not reused
      }

      if (addr)
      {
        fprintf(perf, "IP Address: %s\n", addr);
        free(addr);
        addr = NULL;
      }
      fprintf(perf, "\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
      result = 1;
    }
  }

err:
  if (addr)
  {
    free(addr);
    addr = NULL;
  }
  close(fd);
  return session;
}

SSL_SESSION *tls_v1_2_handshake(SSL_CTX *ctx, SSL_SESSION *session, int rank, char *hostname)
{
  char wbuf[BUF_SIZE], rbuf[BUF_SIZE];
  int fd, ret, timeout = TIMEOUT, rlen, sent, recv = -1, total = -1, offset = 0;
  SSL *ssl;
  struct timeval tv, ts;
  unsigned long start, hs_end, end, base, curr;
  unsigned char *addr;
  fd_set fds, readfds;

  addr = NULL;
  fprintf(perf, "TLSv1.2 Experiment: ");
  fd = open_connection(rank, hostname, PORT, &addr);
  if (fd > maxfd)
    maxfd = fd;
  else if (fd == -500)
  {
    fprintf(perf, "dns failure\n");
    ret = DNS_FAILURE;
    goto err;
  }
  else if (fd < 0)
  {
    fprintf(perf, "socket failure\n");
    ret = SOCK_FAILURE;
    goto err;
  }

  complete = 0;
  result = 0;
  trial = 10;

  rlen = http_make_request(hostname, strlen(hostname), NULL, 0, wbuf, &rlen);
  wbuf[rlen] = 0;

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
  SSL_set_tlsext_host_name(ssl, hostname);

  if (session)
  {
    if (SSL_SESSION_is_resumable(session))
    {
      SSL_set_session(ssl, session);
      fprintf(perf, "1\n"); // Abbreviate handshake
    }
    else
    {
      fprintf(perf, "3\n"); // Session is not resumable
    }
  }
  else
  {
    fprintf(perf, "0\n"); // Full handshake
  }

  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  tv.tv_sec = TIMEOUT/1000;
  tv.tv_usec = 0;

  if (select(maxfd + 1, NULL, &fds, NULL, &tv) == 1)
  {
    int so_error;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

    if (so_error == 0)
    {
      start = get_current_microseconds();
      do_tls_handshake(ssl);
      hs_end = get_current_microseconds();
      
      if (!SSL_is_init_finished(ssl))
      {
        fprintf(perf, "%s Handshake: -1\n", SSL_get_version(ssl));
        fprintf(perf, "%s Total: -1\n", SSL_get_version(ssl));
        goto err;
      }

      sent = -1;
      base = get_current_microseconds();
      while (sent < 0 && ((curr = get_current_microseconds()) < base + DURATION / 10))
      {
        sent = SSL_write(ssl, wbuf, rlen);
  //      sleep(0.1);
      }
      
      if (sent < 0)
      {
        fprintf(perf, "%s Handshake: -1\n", SSL_get_version(ssl));
        fprintf(perf, "%s Total: -1\n", SSL_get_version(ssl));
        goto err;
      }

      base = get_current_microseconds();
      do {
        recv = SSL_read(ssl, rbuf + offset, BUF_SIZE - offset);
  
        if (recv > 0)
        {
          if (total <= 0)
          {
            total = http_parse_response(rbuf, recv);
          }
          offset += recv;

          if (rbuf[0] == '0')
            break;
        }
        else if (recv == 0)
          break;
        recv = -1;
      } while (total > offset && ((curr = get_current_microseconds()) < base + DURATION));

      end = get_current_microseconds();
      //rbuf[offset] = 0;
      //fprintf(perf, "Sent Data (%d bytes): %s\n", sent, wbuf);
      //fprintf(perf, "Received Data (%d bytes): %s\n", offset, rbuf);
      fprintf(perf, "%s Handshake: %.2lf ms\n", SSL_get_version(ssl), 
          (hs_end - start)/1000.0);
      fprintf(perf, "%s Total: %.2lf ms\n", SSL_get_version(ssl), 
          (end - start)/1000.0);

      session = SSL_get0_session(ssl);
      if (SSL_SESSION_is_resumable(session))
      {
        fprintf(perf, "Resumable: 1\n");
      }
      else
      {
        fprintf(perf, "Resumable: 0\n");
      }

      if (SSL_session_reused(ssl))
      {
        fprintf(perf, "Reused: 1\n"); // Reused
      }
      else
      {
        fprintf(perf, "Reused: 0\n"); // Not reused
      }

      if (addr)
      {
        fprintf(perf, "IP Address: %s\n", addr);
        free(addr);
        addr = NULL;
      }
      fprintf(perf, "\n");

      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
      result = 1;
    }
  }

err:
  if (addr)
  {
    free(addr);
    addr = NULL;
  }
  close(fd);
  return session;

}

void enable_tls_extensions(SSL *ssl, char *hostname)
{
  // Server Name Indication (RFC 6066)
  SSL_set_tlsext_host_name(ssl, hostname);

  // Max Fragment Length (RFC 6066)
  SSL_set_tlsext_max_fragment_length(ssl, TLSEXT_max_fragment_length_4096);

  // OCSP Stapling Request (RFC 6066)
  SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

  // Application Layer Protocol Negotiation (RFC 7301)
  //unsigned char alpnlist[] = {
  //  0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
  //};
  unsigned char alpnlist[] = {
    0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
  };

  SSL_set_alpn_protos(ssl, alpnlist, 9);

  // Signed Certificate Timestamp (RFC 6962)
  SSL_enable_ct(ssl, SSL_CT_VALIDATION_PERMISSIVE);

  // Padding Extension (RFC 7685)
  SSL_set_options(ssl, SSL_OP_TLSEXT_PADDING);

  // Post Handshake Auth Extension (RFC 8446)
  SSL_set_post_handshake_auth(ssl, 1);
}

void sighandler(int signum)
{
  signal(SIGALRM, SIG_IGN);
  fprintf(stderr, "sig alarm ");
  signal(SIGALRM, sighandler);
}

int get_next(FILE *fp, int *rank, char *hostname)
{
  FILE *log;
  int ret = -1;
  char tmp[MAX_DOMAIN_LENGTH] = {0, };
  if (!feof(fp))
  {
    ret = fscanf(fp, "%d,%s\n", rank, tmp);
    snprintf(hostname, MAX_DOMAIN_LENGTH, "www.%s", tmp);
    fprintf(stderr, "%d,%s: ", *rank, hostname);
  }

  log = fopen(log_domain_name, "w");

  if (ret == -1)
    fprintf(log, "0,Finished\n");
  else
    fprintf(log, "%d,%s\n", *rank, hostname);
  fclose(log);

  return ret;
}

void make_log_file(int rank, char *hostname, int version)
{
  int index, dlen, flen;
  char *dir_name, *log_fname;
  struct stat st = {0};
  dir_name = NULL;
  log_fname = NULL;

  index = (rank - 1) / 1000;
  dlen = strlen(home_directory) + strlen(date) + 3 + 2;
  flen = strlen(home_directory) + strlen(date) + 3 + 150 + EXT_LENGTH + 4 + 5;
  dir_name = (char *)malloc(dlen + 1);
  log_fname = (char *)malloc(flen + 1);
  dir_name[dlen] = '\0';
  log_fname[flen] = '\0';

  sprintf(dir_name, "%s/%s/%03d", home_directory, date, index);
  if (stat(dir_name, &st) == -1)
    mkdir(dir_name, 0744);

  sprintf(log_fname, "%s/%d_%04x.log", dir_name, rank, version);
  fprintf(stderr, "%s: ", log_fname);
  fp = fopen(log_fname, "w");

  if (dir_name)
  {
    free(dir_name);
    dir_name = NULL;
  }

  if (log_fname)
  {
    free(log_fname);
    log_fname = NULL;
  }
}

void clear_log_file(int err)
{
  switch(err)
  {
    case 1:
      fprintf(stderr, "success");
      break;
    case 2:
      fprintf(stderr, "alert");
      break;
    case 3:
      fprintf(stderr, "server error");
      break;
    default:
      fprintf(stderr, "none");
  }
  fclose(fp);
  fp = NULL;
}

void make_perf_log_file(int rank, char *hostname)
{
  int index, dlen, flen;
  char *dir_name, *log_fname;
  struct stat st = {0};
  dir_name = NULL;
  log_fname = NULL;

  index = (rank - 1) / 1000;
  dlen = strlen(home_directory) + strlen(date) + 3 + 2;
  flen = strlen(home_directory) + strlen(date) + 3 + 150 + EXT_LENGTH + 4;
  dir_name = (char *)malloc(dlen + 1);
  log_fname = (char *)malloc(flen + 1);
  dir_name[dlen] = '\0';
  log_fname[flen] = '\0';

  sprintf(dir_name, "%s/%s/%03d", home_directory, date, index);
  if (stat(dir_name, &st) == -1)
    mkdir(dir_name, 0744);

  sprintf(log_fname, "%s/%d_perf.log", dir_name, rank);
  fprintf(stderr, "%s: ", log_fname);
  perf = fopen(log_fname, "w");

  if (dir_name)
  {
    free(dir_name);
    dir_name = NULL;
  }

  if (log_fname)
  {
    free(log_fname);
    log_fname = NULL;
  }
}

void clear_perf_log_file()
{
  fclose(perf);
  perf = NULL;
}


int open_connection(int rank, const char *hostname, int port, unsigned char **addr)
{   
    int sd, ret, err, optval = 0, trial = 5;
    socklen_t optlen = sizeof(optval);
    char addrstr[100];
    void *ptr;
    struct addrinfo *res;
    struct addrinfo hints;
    FILE *server_error, *client_error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
 
    //signal(SIGALRM, sighandler);

    while (trial > 0)
    {
      trial--;
      //alarm(5);
      err = getaddrinfo(hostname, "443", &hints, &res);
      //signal(SIGALRM, SIG_DFL);
      //alarm(0);

      if (err < 0)
      {
        switch (err)
        {
          case EAI_NONAME:
            trial = -1;
            break;
        }
      }
      else if (err == 0)
      {
        trial = -1;
      }
    }

    if (err < 0)
    {
      switch (err)
      {
        case EAI_AGAIN:
          client_error = fopen(dns_client_error, "a+");
          fprintf(client_error, "%d,%s\n", rank, hostname);
          fclose(client_error);
          break;
        case EAI_NONAME:
          server_error = fopen(dns_server_error, "a+");
          fprintf(server_error, "%d,%s\n", rank, hostname);
          fclose(server_error);
          break;
      }
      return -500;
    }

    inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);
    ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    inet_ntop(res->ai_family, ptr, addrstr, 100);

    fprintf(stderr, "%s ", addrstr);
    (*addr) = (unsigned char *)malloc(16);
    memset((*addr), 0x0, 16);
    memcpy((*addr), addrstr, 15);

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) 
    {
      goto err;
    }
    fcntl(sd, F_SETFL, O_NONBLOCK);

    if (setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto err;

    connect(sd, res->ai_addr, res->ai_addrlen);
    strcpy(ip, inet_ntoa(((struct sockaddr_in *)(res->ai_addr))->sin_addr));
    ip[15] = '\0';

    return sd;
err:
    close(sd);
    fprintf(stderr, " (socket closed in error) ");
    return -1;
}

void msg_callback(int write, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    int i, ht;
    unsigned char *p;
    p = (unsigned char *)buf;

    if (content_type == 256)
    {
      fprintf(fp, "Record Header: %lu\n", len);
      fwrite(p, 1, len, fp);
      fprintf(fp, "\n");
    }
    else
    {
      ht = *p;

      if (content_type == SSL3_RT_HANDSHAKE)
      {
        switch (ht)
        {
          case SSL3_MT_HELLO_REQUEST:
            fprintf(fp, "Hello Request: %lu\n", len);
            break;
          case SSL3_MT_CLIENT_HELLO:
            fprintf(fp, "Client Hello: %lu\n", len);
            break;
          case SSL3_MT_SERVER_HELLO:
            fprintf(fp, "Server Hello: %lu\n", len);
            break;
          case SSL3_MT_NEWSESSION_TICKET:
            fprintf(fp, "New Session Ticket: %lu\n", len);
            break;
          case SSL3_MT_END_OF_EARLY_DATA:
            fprintf(fp, "End of Early Data: %lu\n", len);
            break;
          case SSL3_MT_ENCRYPTED_EXTENSIONS:
            fprintf(fp, "Encrypted Extensions: %lu\n", len);
            break;
          case SSL3_MT_CERTIFICATE:
            fprintf(fp, "Certificate: %lu\n", len);
            break;
          case SSL3_MT_SERVER_KEY_EXCHANGE:
            fprintf(fp, "Server Key Exchange: %lu\n", len);
            break;
          case SSL3_MT_CERTIFICATE_REQUEST:
            fprintf(fp, "Certificate Request: %lu\n", len);
            break;
          case SSL3_MT_SERVER_DONE:
            fprintf(fp, "Server Hello Done: %lu\n", len);
            break;
          case SSL3_MT_CERTIFICATE_VERIFY:
            fprintf(fp, "Certificate Verify: %lu\n", len);
            break;
          case SSL3_MT_CLIENT_KEY_EXCHANGE:
            fprintf(fp, "Client Key Exchange: %lu\n", len);
            break;
          case SSL3_MT_FINISHED:
            fprintf(fp, "Finished: %lu\n", len);
            break;
          case SSL3_MT_CERTIFICATE_URL:
            fprintf(fp, "Certificate URL: %lu\n", len);
            break;
          case SSL3_MT_CERTIFICATE_STATUS:
            fprintf(fp, "Certificate Status: %lu\n", len);
            break;
          case SSL3_MT_SUPPLEMENTAL_DATA:
            fprintf(fp, "Supplemental Data: %lu\n", len);
            break;
          case SSL3_MT_KEY_UPDATE:
            fprintf(fp, "Key Update: %lu\n", len);
            break;
          case SSL3_MT_NEXT_PROTO:
            fprintf(fp, "Next Protocol: %lu\n", len);
            break;
          case SSL3_MT_MESSAGE_HASH:
            fprintf(fp, "Message Hash: %lu\n", len);
            break;
          case SSL3_MT_CHANGE_CIPHER_SPEC:
            fprintf(fp, "Change Cipher Spec: %lu\n", len);
            break;
          default:
            fprintf(fp, "Error: %lu\n", len);
        }
      }
      else if (content_type == SSL3_RT_CHANGE_CIPHER_SPEC)
      {
        fprintf(fp, "Change Cipher Spec: %lu\n", len);
      }
      else if (content_type == SSL3_RT_ALERT)
      {
        fprintf(fp, "Alert: %lu\n", len);
      }
      else if (content_type == SSL3_RT_APPLICATION_DATA)
      {
        fprintf(fp, "Application Data\n");
      }
      else
      {
        return;
      }
      fwrite(p, 1, len, fp);
      fprintf(fp, "\n");
    }
}

SSL_CTX* init_client_ctx(void)
{   
  SSL_METHOD *method;
  SSL_CTX *ctx;
        
  method = (SSL_METHOD *)TLS_client_method(); 
  ctx = SSL_CTX_new(method);
  if ( ctx == NULL )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs");
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
  SSL_CTX_set_ciphersuites(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384");
  load_ecdh_params(ctx);
  return ctx;
}

int is_progress()
{
  return (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS);
}

int is_accessible(int fd, size_t msec, int flag)
{
  fd_set rset, wset;
  struct timeval tv;

  FD_ZERO(&rset);
  FD_ZERO(&wset);

  fd_set *prset = NULL;
  fd_set *pwset = NULL;

  if (SOCK_READABLE & flag)
  {
    FD_SET(fd, &rset);
    prset = &rset;
  }

  if (SOCK_WRITEABLE & flag)
  {
    FD_SET(fd, &wset);
    pwset = &wset;
  }

  tv.tv_sec = msec/1000;
  tv.tv_usec = (msec % 1000) * 1000;

  if (select(fd + 1, prset, pwset, NULL, &tv) <= 0)
    return 0;
  return 1;
}

int is_readable(int fd, size_t msec)
{
  return is_accessible(fd, msec, SOCK_READABLE);
}

int is_writeable(int fd, size_t msec)
{
  return is_accessible(fd, msec, SOCK_WRITEABLE);
}

unsigned long get_current_microseconds()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (1000000 * (tv.tv_sec) + tv.tv_usec);
}

int ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv,
    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
  printf("ssl_tlsext_ticket_key_cb\n");
  return 1;
}

static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
  new_session = 1;
  if (SSL_version(s) == TLS1_3_VERSION)
  {
    //printf("New Session Arrived\n");
    //printf("Available max early data: %d\n", SSL_SESSION_get_max_early_data(sess));
    //SSL_SESSION_print(bp, sess);
  }
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh;
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen)
{
  const uint8_t *get = "GET /";
  const uint8_t *http = " HTTP/1.1";
  const uint8_t *header_before =
    "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Host: ";
  const uint8_t *header_after = 
    "Connection: Keep-Alive\r\n\r\n";
  uint8_t *p;

  p = msg;

  memcpy(p, get, 5);
  p += 5;

  if (clen > 0)
  {
    memcpy(p, content, clen);
    p += clen;
  }
  memcpy(p, http, 9);
  p += 9;

  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;
  memcpy(p, header_before, strlen(header_before));
  p += strlen(header_before);
  memcpy(p, domain, dlen);
  p += dlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  memcpy(p, header_after, strlen(header_after));
  p += strlen(header_after);
  *(p++) = 0;

  *mlen = p - msg;

  return *mlen;
}

int http_parse_response(uint8_t *msg, uint32_t mlen)
{
  int ret;
  uint32_t i, j, l;
  uint8_t *cptr, *nptr, *p;
  cptr = msg;
  ret = INT_MAX;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;
    p = cptr;

    for (i=0; i<l; i++)
    {
      if (p[i] == ' ')
        break;
    }

    if ((l > 0) && (strncmp((const char *)p, "Content-Length:", i) == 0))
    {
      for (j=i+1; j<l; j++)
      {
        if (p[j] == ' ')
          break;
      }
      ret = char_to_int(p + i + 1, j - i);
    }

    cptr = nptr + DELIMITER_LEN;
  }

  return ret;
}

static int char_to_int(uint8_t *str, uint32_t slen)
{
  int i;
  int ret = 0;
  uint8_t ch;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= 10;
        continue;
      case '1':
        ret = ret * 10 + 1;
        continue;
      case '2':
        ret = ret * 10 + 2;
        continue;
      case '3':
        ret = ret * 10 + 3;
        continue;
      case '4':
        ret = ret * 10 + 4;
        continue;
      case '5':
        ret = ret * 10 + 5;
        continue;
      case '6':
        ret = ret * 10 + 6;
        continue;
      case '7':
        ret = ret * 10 + 7;
        continue;
      case '8':
        ret = ret * 10 + 8;
        continue;
      case '9':
        ret = ret * 10 + 9;
        continue;
    }
  }

  return ret;
}
