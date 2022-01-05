#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUF 256

/*
 * TCP Client/Server Implementation project
 * This program is the implementation of the client side
 * 
 * When the program is run with the correct arguments, it will try to
 * connect the port that a server at that ip address is listening to
 * 
 * Once connected, input sent by the client will be received by the server
 * and then the total number of words and characters will be sent back to the
 * client
 * 
 * The server can only handle single line inputs since I wasn't sure from the instructions
 * whether or not to have \n as a delimiter
 * 
 * If the client input is just "exit" the server and client will be disconnected
 */

// Added this from the server.c and changed the printf statements a bit
void PrintOut(int fd, struct sockaddr *addr, size_t addrlen)
{
  printf("established connection with server");
  if (addr->sa_family == AF_INET)
  {
    // Print out the IPV4 address and port

    char astring[INET_ADDRSTRLEN];
    struct sockaddr_in *in4 = (struct sockaddr_in *)(addr);
    inet_ntop(AF_INET, &(in4->sin_addr), astring, INET_ADDRSTRLEN);
    printf(" %s\n", astring);
  }
  else if (addr->sa_family == AF_INET6)
  {
    // Print out the IPV6 address and port

    char astring[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)(addr);
    inet_ntop(AF_INET6, &(in6->sin6_addr), astring, INET6_ADDRSTRLEN);
    printf(" %s\n", astring);
  }
  else
  {
    printf(" ???? address and port ???? \n");
  }
}

void Usage(char *progname); // prints out the requirements for running the program

int LookupName(char *name,
               unsigned short port,
               struct sockaddr_storage *ret_addr,
               size_t *ret_addrlen); // Used to get the sockaddr struct

int Connect(const struct sockaddr_storage *addr,
            const size_t addrlen,
            int *ret_fd); // connects to a socket to establish connection with server


int main(int argc, char **argv)
{
  if (argc != 3)
  {
    Usage(argv[0]);
  }

  unsigned short port = 0;
  if (sscanf(argv[2], "%hu", &port) != 1)
  {
    Usage(argv[0]);
  }

  // Get an appropriate sockaddr structure.
  struct sockaddr_storage addr;
  size_t addrlen;
  if (!LookupName(argv[1], port, &addr, &addrlen))
  {
    Usage(argv[0]);
  }

  // Connect to the remote host.
  int socket_fd;
  if (!Connect(&addr, addrlen, &socket_fd))
  {
    Usage(argv[0]);
  }

  // Prints information about connection to server
  PrintOut(socket_fd, (struct sockaddr *)(&addr), addrlen);

  // Write and read stuff from the remote host in a loop
  char *writebuf = NULL;
  size_t wres;
  while (1)
  {

    // Loop to get valid input from user
    int lineread = getline(&writebuf, &wres, stdin);
    while (lineread == -1)
    {
        printf("Please enter a valid string: ");
        free(writebuf);
        writebuf = NULL;
        lineread = getline(&writebuf, &wres, stdin);
    }

    // Null terminate input string
    writebuf[wres] = '\0';

    // Exit if "exit is typed"
    char *finished = "exit\n";
    int cmp = strcmp(writebuf, finished);
    if (cmp == 0)
    {
      break;
    }

    // Try to write to server
    wres = write(socket_fd, writebuf, wres);
    if (wres == 0)
    {
      printf("socket closed prematurely \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }
    if (wres == -1)
    {
      if (errno == EINTR)
        continue;
      printf("socket write failure \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }

    // try to read from server
      char clientbuf[1024];
      ssize_t res = read(socket_fd, clientbuf, 1023);
      if (res == 0)
      {
        printf("disconnected \n");
        break;
      }

      if (res == -1)
      {
        if ((errno == EAGAIN) || (errno == EINTR))
          continue;

        printf("Error on socket:%d \n ", strerror(errno));
        break;
      }
      clientbuf[res] = '\0';

      // Exit if "exit is typed"
      int cmp2 = strcmp(clientbuf, finished);
      if (cmp2 == 0)
      {
        break;
      }

      // Print server output
      printf("%s", clientbuf);

  }

  // Clean up.
  close(socket_fd);
  return EXIT_SUCCESS;
}

void Usage(char *progname)
{
  printf("usage: %s  hostname port \n", progname);
  exit(EXIT_FAILURE);
}

int LookupName(char *name,
               unsigned short port,
               struct sockaddr_storage *ret_addr,
               size_t *ret_addrlen)
{
  struct addrinfo hints, *results;
  int retval;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // Do the lookup by invoking getaddrinfo().
  if ((retval = getaddrinfo(name, NULL, &hints, &results)) != 0)
  {
    printf("getaddrinfo failed: %s", gai_strerror(retval));
    return 0;
  }

  // Set the port in the first result.
  if (results->ai_family == AF_INET)
  {
    struct sockaddr_in *v4addr =
        (struct sockaddr_in *)(results->ai_addr);
    v4addr->sin_port = htons(port);
  }
  else if (results->ai_family == AF_INET6)
  {
    struct sockaddr_in6 *v6addr =
        (struct sockaddr_in6 *)(results->ai_addr);
    v6addr->sin6_port = htons(port);
  }
  else
  {
    printf("getaddrinfo failed to provide an IPv4 or IPv6 address \n");
    freeaddrinfo(results);
    return 0;
  }

  // Return the first result.
  assert(results != NULL);
  memcpy(ret_addr, results->ai_addr, results->ai_addrlen);
  *ret_addrlen = results->ai_addrlen;

  // Clean up.
  freeaddrinfo(results);
  return 1;
}

int Connect(const struct sockaddr_storage *addr,
            const size_t addrlen,
            int *ret_fd)
{
  // Create the socket.
  int socket_fd = socket(addr->ss_family, SOCK_STREAM, 0);
  if (socket_fd == -1)
  {
    printf("socket() failed: %s", strerror(errno));
    return 0;
  }

  // Connect the socket to the remote host.
  int res = connect(socket_fd,
                    (const struct sockaddr *)(addr),
                    addrlen);
  if (res == -1)
  {
    printf("connect() failed: %s", strerror(errno));
    return 0;
  }

  *ret_fd = socket_fd;
  return 1;
}

