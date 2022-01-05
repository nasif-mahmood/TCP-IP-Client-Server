#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <ctype.h>
#include <err.h>

/*
 * TCP Client/Server Implementation project
 * This program is the implementation of the server side
 * 
 * When the program is run with the correct arguments, the parent thread will set up
 * a listening socket and await for a connection from a client
 * 
 * Once connected, input sent by the client will be received by the server
 * and then the total number of words and characters will be sent back to the
 * client as well as printed on the server side
 *
 * Each client will be processed as its own worker thread
 * 
 * The server can only handle single line inputs correctly
 * 
 * If the client input is just "exit" the server and client will be disconnected
 */

// struct to hold info about the input
struct inputStuff
{
  char *line; // Stores input string
  size_t len;
  ssize_t read; // Length of the string
  char *token;
  char *dlims;    // Delimiters list
  int num_tokens; // number of tokens(words) from input
  int totalchars; // total number of characters from input
};

// information passed to thread
struct myClient
{
  int c_fd;
  struct sockaddr *addr;
  size_t addrlen;
  int sock_family;
};

void Usage(char *progname);                                   // prints out the requirements for running the program
void PrintOut(int fd, struct sockaddr *addr, size_t addrlen); // prints out ip address and port of clients that connect
int Listen(char *portnum, int *sock_family);                  // tries to bind to a socket and returns the file descriptor of it
void HandleClient(int c_fd, struct sockaddr *addr, size_t addrlen,
                  int sock_family); // reads from client and writes to it

void tokenize(struct inputStuff *inputLine); // gets the number of words in the input
void *Mythread(void *arg);                   // each client has its own thread where HandleClient is called

// thread function to create workers
void *Mythread(void *arg)
{

  // create a struct of client attributes and pass it in to the HandleClient function from input parameter
  struct myClient *argClient = (struct myClient *)arg;
  HandleClient(argClient->c_fd,
               argClient->addr,
               argClient->addrlen,
               argClient->sock_family);

  pthread_exit(0);
}

// function to tokenize string
void tokenize(struct inputStuff *inputLine)
{
  // Tokenizing line
  // The input tokens are delimited by " \n"

  inputLine->token = strtok(inputLine->line, inputLine->dlims);
  // Index for number of arguments
  int i = 0;

  // Count number of words and characters until the end of input
  while (inputLine->token != NULL)
  {
    inputLine->totalchars = inputLine->totalchars + strlen(inputLine->token);
    inputLine->num_tokens = inputLine->num_tokens + 1;
    inputLine->token = strtok(NULL, inputLine->dlims);
  }
}

int main(int argc, char **argv)
{
  // Expect the port number as a command line argument.
  if (argc != 2)
  {
    Usage(argv[0]);
  }

  // Bind to a socket using Listen function
  int sock_family;
  int listen_fd = Listen(argv[1], &sock_family);
  if (listen_fd <= 0)
  {
    // We failed to bind/listen to a socket.  Quit with failure.
    printf("Couldn't bind to any addresses.\n");
    return EXIT_FAILURE;
  }

  // Declare variables for threading
  pthread_t tid;
  pthread_attr_t attr;

  // Loop forever, accepting a connection from a client and doing
  // an echo trick to it.
  while (1)
  {
    struct sockaddr_storage caddr;
    socklen_t caddr_len = sizeof(caddr);
    int client_fd = accept(listen_fd,
                           (struct sockaddr *)(&caddr),
                           &caddr_len);
    if (client_fd < 0)
    {
      if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
        continue;
      printf("Failure on accept:%d \n ", strerror(errno));
      break;
    }

    // Handle part is in worker thread
    struct myClient *newClient;
    newClient = malloc(sizeof(struct myClient));

    newClient->c_fd = client_fd;
    newClient->addr = (struct sockaddr *)(&caddr);
    newClient->addrlen = caddr_len;
    newClient->sock_family = sock_family;

    // Create thread for the worker client
    pthread_attr_init(&attr);
    pthread_create(&tid, &attr, Mythread, (void *)newClient);
  }
  pthread_join(tid, NULL);

  // Close socket
  close(listen_fd);

  return EXIT_SUCCESS;
}

void Usage(char *progname)
{
  printf("usage: %s port \n", progname);
  exit(EXIT_FAILURE);
}

// function to print information to console
void PrintOut(int fd, struct sockaddr *addr, size_t addrlen)
{
  printf("worker %ld: established connection with client", pthread_self());

  if (addr->sa_family == AF_INET)
  {
    // Print out the IPV4 address and port

    char astring[INET_ADDRSTRLEN];
    struct sockaddr_in *in4 = (struct sockaddr_in *)(addr);
    inet_ntop(AF_INET, &(in4->sin_addr), astring, INET_ADDRSTRLEN);
    printf(" %s", astring);
    printf("#%d\n", ntohs(in4->sin_port));
  }
  else if (addr->sa_family == AF_INET6)
  {
    // Print out the IPV6 address and port

    char astring[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)(addr);
    inet_ntop(AF_INET6, &(in6->sin6_addr), astring, INET6_ADDRSTRLEN);
    printf(" %s", astring);
    printf("#%d\n", ntohs(in6->sin6_port));
  }
  else
  {
    printf(" ???? address and port ???? \n");
  }
}

// function to create sockets for clients
int Listen(char *portnum, int *sock_family)
{

  // Populate the "hints" addrinfo structure for getaddrinfo().
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;       // IPv6 (also handles IPv4 clients)
  hints.ai_socktype = SOCK_STREAM; // stream
  hints.ai_flags = AI_PASSIVE;     // use wildcard "in6addr_any" address
  hints.ai_flags |= AI_V4MAPPED;   // use v4-mapped v6 if no v6 found
  hints.ai_protocol = IPPROTO_TCP; // tcp protocol
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  // Use argv[1] as the string representation of our portnumber to
  // pass in to getaddrinfo().  getaddrinfo() returns a list of
  // address structures via the output parameter "result".
  struct addrinfo *result;
  int res = getaddrinfo(NULL, portnum, &hints, &result);

  if (res != 0)
  {
    printf("getaddrinfo failed: %s", gai_strerror(res));
    return -1;
  }

  // Loop through the returned address structures until we are able
  // to create a socket and bind to one.  The address structures are
  // linked in a list through the "ai_next" field of result.
  int listen_fd = -1;
  struct addrinfo *rp;
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    listen_fd = socket(rp->ai_family,
                       rp->ai_socktype,
                       rp->ai_protocol);
    if (listen_fd == -1)
    {
      // Creating this socket failed.  So, loop to the next returned
      // result and try again.
      printf("socket() failed:%d \n ", strerror(errno));
      listen_fd = -1;
      continue;
    }

    // Configure the socket; we're setting a socket "option."  In
    // particular, we set "SO_REUSEADDR", which tells the TCP stack
    // so make the port we bind to available again as soon as we
    // exit, rather than waiting for a few tens of seconds to recycle it.
    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
               &optval, sizeof(optval));

    // Try binding the socket to the address and port number returned
    // by getaddrinfo().
    if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0)
    {
      // Return to the caller the address family.
      *sock_family = rp->ai_family;
      break;
    }

    // The bind failed.  Close the socket, then loop back around and
    // try the next address/port returned by getaddrinfo().
    close(listen_fd);
    listen_fd = -1;
  }

  // Free the structure returned by getaddrinfo().
  freeaddrinfo(result);

  // If we failed to bind, return failure.
  if (listen_fd == -1)
    return listen_fd;

  // Success. Tell the OS that we want this to be a listening socket.
  if (listen(listen_fd, SOMAXCONN) != 0)
  {
    printf("Failed to mark socket as listening:%d \n ", strerror(errno));
    close(listen_fd);
    return -1;
  }

  // Return to the client the listening file descriptor.
  return listen_fd;
}

// calculates words and word count from client and sends it back
void HandleClient(int c_fd, struct sockaddr *addr, size_t addrlen,
                  int sock_family)
{
  // Print out information about the client.
  PrintOut(c_fd, addr, addrlen);

  // Loop, reading data and echo'ing it back, until the client
  // closes the connection.
  while (1)
  {
    char clientbuf[1024];
    ssize_t res = read(c_fd, clientbuf, 1023);
    if (res == 0)
    {
      printf("worker %ld: client terminated \n", pthread_self());
      break;
    }

    if (res == -1)
    {
      if ((errno == EAGAIN) || (errno == EINTR))
        continue;

      printf(" Error on client socket:%d \n ", strerror(errno));
      break;
    }
    clientbuf[res] = '\0';

    // Creates a struct out of the input to obtain number of words and characters
    struct inputStuff clientInput;
    clientInput.line = strdup(clientbuf);
    clientInput.dlims = " \n";
    clientInput.len = 0;
    clientInput.num_tokens = 0;
    clientInput.totalchars = 0;
    tokenize(&clientInput);

    printf("worker %ld: received message from client. # words = %d and # characters = %d\n", pthread_self(), clientInput.num_tokens, clientInput.totalchars);

    char *wordsnchars = "# of words: ";

    // Convert integers and concat with the line that will be written
    asprintf(&wordsnchars, "# of words = %d and # of chars = %d\n", clientInput.num_tokens, clientInput.totalchars);

    int written = 0;
    int wr;        

    // Write in a loop to error check
    while (written < strlen(wordsnchars))
    {
      if ((wr = write(c_fd, wordsnchars + written, strlen(wordsnchars) - written)) < 0)
      {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        err(EXIT_FAILURE, "Could not write()");
      }

      written += wr;
    }
  }

  close(c_fd);
}
