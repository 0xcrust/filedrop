#include "filedrop.h"

/*
Filedrop is a server for fast file uploads and requests.

Features:
    * Supports parallel connections and concurrent uploads
    * No limits on file size
    * Supports SSL for secure file sharing(optional)
*/

/* TODO:
*   Handle errors properly. Some should fail and exit, some shouldn't.
*   Check client_info and remove redundant fields if any.
*   Find a way to get the file format or desired filename from the user.
*   Allow user to upload multiple files in one connection.
*   Create a unique folder for each user
*   Add proper commenting and some measure of documentation.
*   Write function prototypes in filedrop.h and move functions below
*   Make cross-platform
*   Check function return types
*   Clear redundant printfs
*   Write debug messages to a file
*   Sort out certificates.
*   Important!! Fix issues with dropped bytes during video transfer that prevents it from playing()
//////// Issue with the above diagnosed. 5 bytes are being dropped at the beginning of the file.
//////// Further diagnosis: try_make_ssl_connection is the cause of the problem.
//////// A simple solution could just be to send the files separately
*   Important!! Do research. It might turn out that we have to default to a normal connection for large uploads, rather than SSL
*/

// TODO: This should be split into a `client` struct and a `upload` struct
// A client should be able to have multiple simultaneous uploads
struct client_info {
    int client_id;
    struct sockaddr_storage address;
    socklen_t address_length;
    char address_p[NAME_LENGTH];
    int socket;
    char upload_buffer[BUFFERSIZE];
    int bytes_uploaded;
    SSL *ssl_connection;
    FILE *dest_file;
    struct client_info *next;
};

static struct client_info *active_clients = 0;

// Initialize OpenSSL and setup context for managing connections
void ssl_initialize(SSL_CTX** ssl_context) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Failed creating SSL context.\n");
        exit(1); 
    }

    if (!SSL_CTX_use_certificate_file(ssl_ctx, "cert/cert.pem", SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ssl_ctx, "cert/key.pem", SSL_FILETYPE_PEM)) 
    {
        fprintf(stderr, "Missing one or both files for ssl credentials");
        SSL_CTX_free(ssl_ctx); // is this necessary?
        exit(1);
    }

    *ssl_context = ssl_ctx;
    printf("SSL initialized.\n");
}

// Find the client_info for a particular socket s
struct client_info *get_client(SOCKET s) {
    struct client_info *client_info = active_clients;
    
    while(client_info) {
        if (client_info->socket == s) {
            printf("Found socket %d in active_clients list\n", s);
            printf("Location: %ld\n", (long) client_info);
            return client_info;
        }
            
            
        client_info = client_info->next;
    }

    return 0;
}

// Create a new client and add to global list of active clients
struct client_info *create_new_client(SOCKET s) {
    if (get_client(s) != 0) {
        fprintf(stderr, "Socket in use by existing client\n");
        return 0; 
    }

    struct client_info *new = (struct client_info*) calloc(1, sizeof(struct client_info));
    if (!new) {
        fprintf(stderr, "Failed allocating memory for new client_info struct\n");
        return 0;
    }

    new->client_id = active_clients ? active_clients->client_id + 1 : 0;
    new->address_length = sizeof(new->address);
    new->next = active_clients;
    new->socket = s;
    active_clients = new;
    return new;
}

// Obtain a client's presentation address and write it to its struct
void set_presentation_address(struct client_info *client) {
    getnameinfo(
        (struct sockaddr*) &client->address, client->address_length,
        client->address_p, NAME_LENGTH, 0, 0,
        NI_NUMERICHOST
    );
    return;
}

struct client_info *accept_connection(SOCKET server) {
    struct sockaddr_storage incoming_address;
    socklen_t incoming_address_len = sizeof(incoming_address);

    int new_socket = accept(
        server,
        (struct sockaddr*) &incoming_address,
        &incoming_address_len
    );

    printf("-> new socket: %d\n", new_socket);

    if (new_socket < 0) {
        fprintf(stderr, "Call to accept() failed: %s\n", strerror(errno));
        return 0;
    }

    struct client_info *new_client = create_new_client(new_socket);
    printf("new_client: %ld\n", (long) new_client);
    if (!new_client) {
        fprintf(stderr, "create_new_client() failed\n");
        return 0;
    }
    printf("new client created?\n");

    new_client->address = incoming_address;
    new_client->address_length = incoming_address_len;
    set_presentation_address(new_client);
    printf("values set. returning...\n");

    return new_client;
    printf("still here? doubtful\n");
}


void set_socket_non_blocking(int sock) {
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return;
    }
    if ((fcntl(sock, F_SETFL, flags | O_NONBLOCK)) < 0) {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return;
    }
}

void set_socket_blocking(int sock) {
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        fprintf(stderr, "Set_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return;
    }
    if ((fcntl(sock, F_SETFL, flags ^ O_NONBLOCK)) < 0) {
        fprintf(stderr, "Set_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return;
    }
}

// Tries to make an ssl_connection. Returns no value but its result can be 
// validated by checking for `ci->ssl_connection`
void try_make_ssl_connection(SSL_CTX *ssl_context, struct client_info *ci) {
    SSL *ssl_conn = SSL_new(ssl_context);

    if (!ssl_conn) {
        fprintf(stderr, "Failed creating new ssl connection %d", ci->client_id);
        return;
    }

    SSL_set_fd(ssl_conn, ci->socket);
    set_socket_non_blocking(ci->socket);
    

    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(ci->socket, &reads);

    fd_set writes;
    FD_ZERO(&writes);
    FD_SET(ci->socket, &writes);
    //int ret;

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    // TODO handle: It blocks in a normal connection. Big issue!(solved now!)
    while(!SSL_is_init_finished(ssl_conn)) {
        int ret = SSL_accept(ssl_conn);
        printf("SSL_accept read %d bytes\n", ret);
        fd_set write = writes;
        fd_set read = reads;
        //int ret;

        switch (SSL_get_error(ssl_conn, ret)) {
            case SSL_ERROR_NONE:
                printf("case ssl_error_none\n");
                break;

            case SSL_ERROR_WANT_WRITE: 
                printf("case ssl_error_want_write\n");
                fd_set write = writes;
                if ((ret = select(ci->socket + 1, 0, &writes, 0, &timeout)) < 0) {
                    fprintf(stderr, "select() call failed: (%s)\n", strerror(errno));
                }
                if (ret == 0) {
                    set_socket_blocking(ci->socket);
                    return;
                }
                //if (ret == 0) return; // select() timed out
                break;

            case SSL_ERROR_WANT_READ: 
                printf("case ssl_error_want_read\n");
                fd_set read = reads;
                if ((ret = select(ci->socket+1, &reads, 0, 0, &timeout)) < 0) {
                    fprintf(stderr, "select() call failed: (%s)\n", strerror(errno));
                }
                if (ret == 0) {
                    set_socket_blocking(ci->socket);
                    return;
                }
                //if (select_ret == 0) return; // select() timed out
                break;

            default:
                fprintf(stderr, "Unexpected. SSL_accept() handshake failed: ");
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "\n");

                SSL_shutdown(ssl_conn);
                SSL_free(ssl_conn);
                set_socket_blocking(ci->socket);
                return;
        }
    }
    set_socket_blocking(ci->socket);
    ci->ssl_connection = ssl_conn;
    return;
}

void drop_client(struct client_info *client) {
    struct client_info *client_pointer = get_client(client->socket);
    if (client_pointer == 0) {
        fprintf(stderr, "Client info does not exist for socket %d.\n", client->socket);
        return;
    }

    if (client->ssl_connection) {
        SSL_shutdown(client->ssl_connection);
        SSL_free(client->ssl_connection);
    }

    printf("closing socket %d\n", client->socket);
    close(client->socket);
    if (client->dest_file) fclose(client->dest_file);

    struct client_info **p = &client;
    *p = client->next;
    if (client_pointer == active_clients) {
        active_clients = client_pointer->next;
    }
    free(client_pointer);

    return;
}

// TODO: On upload done, send EOF / shutdown to connection
// Use enums to manage state machines?
int handle_upload(struct client_info *ci, char* filename) { // TODO: Let filename be decided inside
// this function, not outside it
    printf("Continuing upload...\n");
    SSL *ssl = ci->ssl_connection;

    if (!ci->dest_file) { // if file is uninitialized
        time_t time_var;
        time(&time_var);

        // TODO: Decide on a good naming convention for files
        // Also decide on how to properly arrange different uploads
        // for different users.

        //char filename[100];
        //char *filename = "tests/test.c";
        //sprintf(filename, "%d_%s", ci->client_id, ctime(&time_var));
        printf("-> Creating file with name {%s}.\n", filename);
        
        FILE *new_file = fopen(filename, "w");
        if (!new_file) {
            fprintf(stderr, "Failed creating file.\n");
            return -1;
        }
        ci->dest_file = new_file;
    }

    int bytes_received;
    // TODO: Call recursively?
    // TODO: IMPORTANT WHEN WAKE UP: IMPROVE DEBUGGING BY SEPARATING
    // ERROR PRINTING FOR BOTH CONDITIONS AND USING STRERROR
    if (ci->ssl_connection) {
        bytes_received = SSL_read(
            ssl, 
            ci->upload_buffer, 
            sizeof(ci->upload_buffer)//TODO: Consider making it sizeof(ci->upload_buffer) - 1
        );
        if (bytes_received < 1) {
            fprintf(stderr, "-> SSL_read() failed: ");
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "\n");
            return -1;
        }
    } 
    if (!ci->ssl_connection) {
        bytes_received = recv(
            ci->socket,
            ci->upload_buffer,
            sizeof(ci->upload_buffer), 0 
        );
        if (bytes_received < 1) {
            fprintf(stderr, "-> recv() failed: %s\n", strerror(errno));
            return -1;
        }
    }

    // TODO: Split handling of a failure from handling of a completed upload.
    // Don't return -1 for both

    printf("Received %d bytes from %s\n", bytes_received, ci->address_p);
    printf("Received: \n%.*s\n from stream", bytes_received, ci->upload_buffer);
    printf("Writing %d bytes to file.\n", bytes_received);
    ci->bytes_uploaded+=bytes_received;

    char last = ci->upload_buffer[sizeof(ci->upload_buffer) - 1];
    printf("possible EOF char: %c\n", last);

    int remaining = bytes_received;
    while(remaining > 0) {
        int bytes_written = fwrite(ci->upload_buffer, 1, bytes_received, ci->dest_file);
        printf("Wrote: \n%.*s\n to file", bytes_written, ci->upload_buffer);
        if (fwrite < 0) {
            return -1;
        }
        remaining-=bytes_written;
    }
    fflush(ci->dest_file);

    return bytes_received;
}

// TODO: Re-examine file permissions
void setup_storage_dir(char *filename) {
    struct stat sb;
    if (stat(filename, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return;
    }

    if (mkdir("storage", 755) != 0) {
        fprintf(
            stderr, 
            "Failed creating directory `storage` with permissions (755): %s\n",
            strerror(errno)
        );
        return;
    } 
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr, "usage: filedrop <port_no>\n");
        return 1;
    }

    SSL_CTX *context;
    ssl_initialize(&context);

    printf("-> Configuring bind address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *local_address;
    getaddrinfo(INADDRANY, argv[1], &hints, &local_address);

    printf("-> Creating socket...\n");
    int server;
    server = socket( 
        local_address->ai_family, 
        local_address->ai_socktype, 
        local_address->ai_protocol
    );

    if (server < 0) {
        fprintf(stderr, "socket() call failed: %s", strerror(errno));
        return 1;
    }

    printf("-> Binding socket to port %s...\n", argv[1]);
    if (bind(server, local_address->ai_addr, local_address->ai_addrlen)) 
    {
        fprintf(stderr, "bind() call failed: %s\n", strerror(errno));
        return 1;
    }
    freeaddrinfo(local_address);
    
    if (listen(server, BACKLOG) != 0) {
        fprintf(stderr, "listen() call failed: %s\n", strerror(errno));
        return 1;
    }
    printf("-> Server active and listening for connections with a queue limit of %d\n", BACKLOG);

    setup_storage_dir("storage");
    printf("-> Finished setting up storage folder!\n");

    fd_set master;
    FD_ZERO(&master);
    FD_SET(server, &master);
    int max_socket = server;

    printf("-> Starting loop to accept connections...\n");
    while(1) {
        fd_set reads = master;
        printf("-> Server waiting for reads...\n");
        if (select(max_socket + 1, &reads, 0, 0, 0) < 0) {
            fprintf(stderr, "select() call failed: %s\n", strerror(errno));
            return 1;
        }

        for (int i = 1; i <= max_socket; ++i) {
            if (FD_ISSET(i, &reads)) {
                printf("Selected socket %d\n", i);
                if (i == server) {
                    printf("-> New incoming connection.\n");
                    struct client_info *new_client = accept_connection((SOCKET) i);
                    if (!new_client) {
                        fprintf(stderr, "accept_connection() failed\n");
                        printf("connection failed?\n");
                        FD_CLR(i, &master);
                        continue; 
                    }
                    printf("-> New connection made from %s\n", new_client->address_p);
                    FD_SET(new_client->socket, &reads);
                    if (new_client->socket > max_socket)
                    {
                        max_socket = new_client->socket;
                    }

                    printf("-> Setting up ssl connection...\n");
                    // TODO fix: It blocks
                    try_make_ssl_connection(context, new_client);
                    if (!new_client->ssl_connection) {
                        printf("Warning! ssl_connection not made, uploads will default to less safe channels\n");
                    } else {
                        printf("ssl connection successful. using %s\n", SSL_get_cipher(new_client->ssl_connection));
                    }
                } else {
                    printf("-> Reading from established connection\n");
                    struct client_info *client = get_client(i);
                    int bytes_uploaded = handle_upload(client, argv[2]);
                    printf("handle___upload() return value: %d\n", bytes_uploaded);

                    // TODO: Distinguish from error and file upload completion
                    if (bytes_uploaded < 0) { //TODO: also handle if bytes_uploaded < sizeof(client->upload_buffer)
                        // (contd:) This would also mean that the read is complete
                        // TODO: Fix! Not every termination is due to an error.
                        printf("-> Client %s got an error. Dropping.. \n", client->address_p);
                        printf("-> Uploaded %d bytes in total\n", client->bytes_uploaded);
                        drop_client(client); //TODO: no longer being triggered for some reason
                        FD_CLR(i, &master);
                    } else { // so we can read again
                        FD_SET(i, &master);
                    }
                }
            } 
        } // End loop to max_socket
    } // End while(1) loop

    printf("Shutting down server...\n");
    struct client_info *client = active_clients;
    while(client) {
        struct client_info *next = client->next;
        drop_client(client);
        client = next;
    }
    close(server);
    SSL_CTX_free(context);
}