#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SOCKET int
#define INADDRANY 0
#define BACKLOG 20
#define BUFFERSIZE 56626
#define NAME_LENGTH 100
#define F_NAME_LENGTH 100 

#define CLIENT_FOUND 1
#define CLIENT_NOT_FOUND 0