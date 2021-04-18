#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/logs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

//#include "log_client.h"

#define FAIL          -1
#define BUF_SIZE      16384
#define DHFILE        "dh1024.pem"
#define MAX_HOST_LEN  256

#define DELIMITER     "\r\n"
#define DELIMITER_LEN 2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12

#define MAX_FILE_NAME_LEN 256
#define MAX_THREADS 100

struct rinfo
{
  FILE *fp;
  int client;
  char *port;
  SSL_CTX *ctx;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size;
  uint32_t sent;
};

int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
#ifdef TIME_LOG
log_t time_log[NUM_OF_LOGS];
#endif /* TIME_LOG */
int running = 1;
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
int fetch_cert(SSL *ssl, int *ad, void *arg);

void init_thread_config();
int get_thread_index();
void *run(void *rinfo);

pthread_t threads[MAX_THREADS];
pthread_attr_t attr;

void int_handler(int dummy)
{
  EDGE_LOG("End of experiment");
  running = 0;
  exit(0);
}

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	int i, rc, server, client, tidx;
	char *portnum, *prefix;
  void *status;

	if ( count != 3 )
	{
		printf("Usage: %s <portnum> <label>\n", strings[0]);
		exit(0);
	}

  signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
  prefix = strings[2];

	ctx = init_server_ctx();
  load_ecdh_params(ctx);
	load_certificates(ctx);


	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

  init_thread_config();

	while (running)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      struct rinfo *rinfo = (struct rinfo *)malloc(sizeof(struct rinfo));
      memset(rinfo, 0x0, sizeof(struct rinfo));
      rinfo->client = client;
      rinfo->port = portnum;
      rinfo->ctx = ctx;
      tidx = get_thread_index();
      rc = pthread_create(&threads[tidx], &attr, run, rinfo);

      if (rc < 0)
      {
        printf("Error in pthread creation\n");
        exit(1);
      }

      pthread_attr_destroy(&attr);
    }
	}

  for (i=0; i<MAX_THREADS; i++)
  {
    rc = pthread_join(threads[tidx], &status);

    if (rc)
    {
      printf("Error in join\n");
      exit(1);
    }
  }

	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

void *run(void *rinfo)
{
  SSL *ssl;
  struct rinfo *r;
  int sent = -1, rcvd = -1, offset = 0, success = 1, mlen = 0;
  r = (struct rinfo *)rinfo;
  char rbuf[BUF_SIZE] = {0};
  char wbuf[BUF_SIZE] = {0};

  EDGE_LOG("New Connection is accepted");
  ssl = SSL_new(r->ctx);
  SSL_set_fd(ssl, r->client);      
  SSL_set_time_log(ssl, time_log);
  SSL_disable_ec(ssl);

  RECORD_LOG(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT);
  if (SSL_accept(ssl) == FAIL)
  {
    ERR_print_errors_fp(stderr);
    success = 0;
  }
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_AFTER_TLS_ACCEPT);
  INTERVAL(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT, SERVER_AFTER_TLS_ACCEPT);
  printf("Established: %s\n", SSL_get_version(ssl));

  if (success)
  {
    while (rcvd < 0)
      rcvd = SSL_read(ssl, rbuf, BUF_SIZE);

    RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START);
    EDGE_LOG("rcvd: %d", rcvd);
    if (rcvd > 0)
    {
      EDGE_LOG("before http parse requeset");
      http_parse_request(rbuf, rcvd, r);
      fetch_content(wbuf, r);
      EDGE_LOG("content length: %d, content sent: %d", r->size, r->sent);
    }

    while (r->size > r->sent)
    {
      if ((r->size - r->sent) > BUF_SIZE)
        mlen = BUF_SIZE;
      else
        mlen = r->size - r->sent;
      r->sent += SSL_write(ssl, wbuf, mlen);
      fetch_content(wbuf, r);
      EDGE_LOG("content length: %d, content sent: %d", r->size, r->sent);
    }

    RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_END);
    INTERVAL(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START, SERVER_SERVE_HTML_END);
    EDGE_LOG("HTTP Request Length: %d, HTTP Response Length: %d", rcvd, r->size);

    EDGE_LOG("SERVER: Send the HTTP Test Page Success: %d", r->sent);
  
    mlen = 0;
    offset = 0;
    rcvd = -1;
    sent = -1;
  }
  close(r->client);
  SSL_free(ssl);
  ssl = NULL;
  success = 1;

  memset(rbuf, 0x0, BUF_SIZE);
  memset(wbuf, 0x0, BUF_SIZE);

  return NULL;
}

int open_listener(int port)
{   
  int sd;
	struct sockaddr_in addr;
  int enable;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	enable = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    perror("setsockopt(SO_REUSEADDR) failed");
    abort();
  }

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 100) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* init_server_ctx(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLS_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		EDGE_LOG("SSL_CTX init failed!");
		abort();
	}

#ifdef TLS13
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#else
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif /* TLS13 */

#ifdef SESSION_RESUMPTION
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
#else
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#endif /* SESSION_RESUMPTION */

  SSL_CTX_set_cipher_list(ctx, "ALL");

	return ctx;
}

void load_certificates(SSL_CTX* ctx)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_tlsext_servername_callback(ctx, fetch_cert);
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
  {
    perror("Couldn't open DH file");
  }

  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
  {
    perror("Couldn't set DH parameters");
  }
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int fetch_cert(SSL *ssl, int *ad, void *arg)
{
  EDGE_LOG("Start: fetch_cert: ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
  (void) ad;
  (void) arg;

  int ret;
  uint8_t crt_path[MAX_HOST_LEN];
  uint8_t priv_path[MAX_HOST_LEN];
  uint8_t *p;
  uint32_t len;

  if (!ssl)
    return SSL_TLSEXT_ERR_NOACK;

  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  EDGE_LOG("Received name: %s", name);

  if (!name || name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  memset(crt_path, 0x0, MAX_HOST_LEN);
  memset(priv_path, 0x0, MAX_HOST_LEN);

  p = crt_path;
  len = strlen(name);
  memcpy(p, name, len);

  ret = mkdir(p, 0775);
  if (ret < 0)
  {
    if (errno == EEXIST)
    {
      EDGE_MSG("The directory exists");
    }
    else
    {
      EDGE_MSG("Other error");
    }
  }

  p += len;
  memcpy(p, "/cert.der", 9);

  p = priv_path;
  len = strlen(name);
  memcpy(p, name, len);

  p += len;
  memcpy(p, "/priv.der", 9);

  EDGE_LOG("crt_path: %s", crt_path);
  EDGE_LOG("priv_path: %s", priv_path);

  if (SSL_use_certificate_file(ssl, crt_path, SSL_FILETYPE_ASN1) != 1)
  {
    EDGE_LOG("Loading the certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  EDGE_MSG("Loading the certificate success");

  if (SSL_use_PrivateKey_file(ssl, priv_path, SSL_FILETYPE_ASN1) != 1)
  {
    EDGE_LOG("Loading the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }
  
  EDGE_MSG("Loading the private key success");

  if (SSL_check_private_key(ssl) != 1)
  {
    EDGE_LOG("Checking the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  EDGE_MSG("Checking the private key success");

  EDGE_MSG("Finished: fetch_cert");
  return SSL_TLSEXT_ERR_OK;
}

size_t fetch_content(uint8_t *buf, struct rinfo *r)
{
  EDGE_LOG("Start: fetch_content: buf: %p, r: %p", buf, r);

	const char *resp = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"\r\n";

  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen;
  rlen = 0;

  if (r->size != 0 && r->size <= r->sent)
  {
    fclose(r->fp);
    goto ret;
  }

  if (!(r->fp))
  {
    memset(path, 0x0, MAX_HOST_LEN);
    p = path;

    memcpy(p, r->domain, r->dlen);
    p += r->dlen;
  
    memcpy(p, r->content, r->clen);
    EDGE_LOG("path: %s", path);

    r->fp = fopen(path, "rb");

    if (!(r->fp))
    {
      EDGE_LOG("Error in opening the file");
      r->size = -1;
      goto ret;
    }
  }

  if (r->size == 0)
  {
    fseek(r->fp, 0L, SEEK_END);
    r->size = total = ftell(r->fp);
    sz = total - r->sent;
    EDGE_LOG("sz: %ld, r->sent: %u", sz, r->sent);
  }

  EDGE_LOG("r->size: %u, r->sent: %u", r->size, r->sent);

  memset(buf, 0x0, BUF_SIZE);
  p = buf;
  
  if (r->sent == 0)
  {
    snprintf(p, BUF_SIZE, resp, sz);
    rlen = strlen(buf);
    r->size += rlen;
    p += rlen;
  }

  fseek(r->fp, r->sent, SEEK_SET);

  if (r->size - r->sent > BUF_SIZE)
  {
    if (r->sent == 0)
      sz = BUF_SIZE - (r->sent);
    else
      sz = BUF_SIZE;
  }
  else
  {
    sz = r->size - r->sent;
  }
  fread(p, 1, sz, r->fp);

  EDGE_LOG("sz: %ld, rlen: %d", sz, rlen);
  EDGE_MSG("Finished: fetch_content");
ret:
  return r->size;
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r)
{
  EDGE_LOG("Start: http_parse_request: msg: %p, mlen: %d, rinfo: %p", msg, mlen, r);
  (void) mlen;
  int l;
  uint8_t *cptr, *nptr, *p, *q, *tmp;
  struct rinfo *info;

#ifdef DEBUG
  uint8_t buf[MAX_HOST_LEN] = {0};
#endif /* DEBUG */
  
  info = r;
  cptr = msg;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l+1] = 0;
    EDGE_LOG("Token (%d bytes): %s", l, buf);
#endif /* DEBUG */

    p = cptr;
    
    while (*p == ' ')
      p++;

    if ((l > 0) && (strncmp((const char *)p, "GET", 3) == 0))
    {
      p += 3;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ' && *q != '\r')
        q++;

      if (q - p == 1)
      {
        info->content = (uint8_t *)malloc(INDEX_FILE_LEN + 1);
        memset(info->content, 0x0, INDEX_FILE_LEN + 1);
        memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
        info->clen = INDEX_FILE_LEN;
      }
      else
      {
        info->content = (uint8_t *)malloc(q - p + 1);
        memset(info->content, 0x0, q - p + 1);
        memcpy(info->content, p, q - p);
        info->clen = q - p;
      }
    }

    if ((l > 0) && (strncmp((const char *)p, "Host:", 5) == 0))
    {
      p += 5;

      while (*p == ' ')
        p++;

      tmp = p;
      while ((*tmp) != ':' && tmp != nptr)
        tmp++;

      info->domain = (uint8_t *)malloc(tmp - p + 1);
      memset(info->domain, 0x0, tmp - p + 1);
      memcpy(info->domain, p, tmp - p);
      info->dlen = tmp - p;
    }

    cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, MAX_HOST_LEN);
#endif /* DEBUG */
  }

  EDGE_LOG("Domain name in parser (%d bytes): %s", info->dlen, info->domain);
  EDGE_LOG("Content name in parser (%d bytes): %s", info->clen, info->content);
  EDGE_LOG("Finished: http_parse_request");

  return 1;
}

void init_thread_config(void)
{
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
  {
    if (!threads[i])
    {
      ret = i;
      break;
    }
  }

  return ret;
}
