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
#include <stdlib.h>
#include <getopt.h>

#include "err.h"

#define TIMEOUT 3000
#define MAX_DOMAIN_LENGTH 255
#define FAIL    -1
#define EXT_LENGTH 4
#define PORT 443

int open_connection(const char *hostname, int port);
int get_next(FILE *fp, int *rank, char *hostname);
void make_log_file(int rank, char *hostname);
void clear_log_file(int err);
int is_progress();
int is_accessible(int fd, size_t msec, int flag);
int is_readable(int fd, size_t msec);
int is_writeable(int fd, size_t msec);
SSL_CTX* init_client_ctx(void);
FILE *fp, *err, *ips;
unsigned char *home_directory, *date;
int complete, result, trial;
char ip[16];

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
  int rank, serial, e;
	int i, c, rc, ret, maxfd, state, ilen, elen, timeout = TIMEOUT, random;
  char hostname[MAX_DOMAIN_LENGTH] = {0, };
  char log_directory[MAX_DOMAIN_LENGTH] = {0, };
  char *list, *ips_fname, *err_fname, *pname;
  SSL *ssl;
  SSL_CTX *ctx;
  struct timeval tv, ts;
  fd_set fds, readfds;
  double stime;
  struct stat st = {0};
  time_t now;
  unsigned char buf[11] = {0, };

  pname = argv[0];

  list = NULL;
  home_directory = NULL;
  serial = -1;
  e = ERR_NONE;

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

  srand(now);
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  gettimeofday(&ts, NULL);
  elen = strlen(home_directory) + strlen(date) + 30;
  err_fname = (char *)malloc(elen + 1);
  sprintf(err_fname, "%s/%s/err.log.%lu", home_directory, date, ts.tv_sec);
  err_fname[elen] = '\0';
  err = fopen(err_fname, "w");

  ilen = strlen(home_directory) + strlen(date) + 30;
  ips_fname = (char *)malloc(ilen + 1);
  sprintf(ips_fname, "%s/%s/ips_%d.csv", home_directory, date, serial);
  ips_fname[ilen] = '\0';
  ips = fopen(ips_fname, "w");

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
    fd = open_connection(hostname, PORT);
    if (fd > maxfd)
      maxfd = fd;

    else if (fd == -500)
    {
      fprintf(stderr, "dns failure\n");
      fprintf(err, "%d,%s: dns failure\n", rank, hostname);
      continue;
    }

    else if (fd < 0)
    {
      fprintf(stderr, "socket failure\n");
      continue;
    }

    fprintf(ips, "%d, %s, %s\n", rank, hostname, ip);
    complete = 0;
    result = 0;
    trial = 3;
    ctx = init_client_ctx();
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, hostname);

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
        make_log_file(rank, hostname);

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
                fprintf(err, "%d,%s: alert\n", rank, hostname);
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
        SSL_free(ssl);
        clear_log_file(complete);
        result = 1;
      }
    }
    else
    {
      fprintf(stderr, "timeout");
      close(fd);
      fprintf(stderr, " (socket closed) ");
      result = 1;
      fprintf(err, "%d,%s: timeout\n", rank, hostname);
    }
    if (result)
    {
      close(fd);
      fprintf(stderr, " (socket closed) \n");
    } 
    else
    {
      fprintf(err, "%d,%s: none\n", rank, hostname);
      close(fd);
      fprintf(stderr, " (socket closed) none\n");
    }
  }
  SSL_CTX_free(ctx);
  fclose(err);
  fclose(ips);

  return 0;
}

void sighandler(int signum)
{
  signal(SIGALRM, SIG_IGN);
  fprintf(stderr, "sig alarm ");
  signal(SIGALRM, sighandler);
}

int get_next(FILE *fp, int *rank, char *hostname)
{
  int ret = -1;
  char tmp[MAX_DOMAIN_LENGTH] = {0, };
  if (!feof(fp))
  {
    ret = fscanf(fp, "%d,%s\n", rank, tmp);
    //snprintf(hostname, MAX_DOMAIN_LENGTH, "www.%s", tmp);
    snprintf(hostname, MAX_DOMAIN_LENGTH, "%s", tmp);
    fprintf(stderr, "%d,%s: ", *rank, hostname);
  }

  return ret;
}

void make_log_file(int rank, char *hostname)
{
  int index, dlen, flen;
  char *dir_name, *log_fname;
  struct stat st = {0};

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

  sprintf(log_fname, "%s/%d.log", dir_name, rank);
  fprintf(stderr, "%s: ", log_fname);
  fp = fopen(log_fname, "w");
  free(dir_name);
  free(log_fname);
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
}

int open_connection(const char *hostname, int port)
{   
    int sd, ret, err, optval = 0;
    socklen_t optlen = sizeof(optval);
    char addrstr[100];
    void *ptr;
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
 
    signal(SIGALRM, sighandler);

    alarm(5);
    err = getaddrinfo(hostname, "443", &hints, &res);
    signal(SIGALRM, SIG_DFL);
    alarm(0);

    if (err != 0)
      return -500;

    inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);
    ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    inet_ntop(res->ai_family, ptr, addrstr, 100);

    fprintf(stderr, "%s ", addrstr);

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) goto err;
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
      if (ht == content_type) return;
      (ht - 1)? fprintf(fp, "Server Hello: %lu\n", len) : fprintf(fp, "Client Hello: %lu\n", len);
      fwrite(p, 1, len, fp);
      fprintf(fp, "\n");
    }

    if (content_type == 22 && ht == 2)
    {
      close(SSL_get_fd(ssl));
      complete = 1;
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

	SSL_CTX_set_msg_callback(ctx, msg_callback);

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
