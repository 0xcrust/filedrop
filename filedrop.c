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
*/

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
        if (client_info->socket == s) 
            return client_info;
            
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

    printf("accepted?\n");

    /*
    printf("set non-blocking:\n");
    int flags;
    flags = fcntl(new_socket, F_GETFL, 0);
    fcntl(new_socket, F_SETFL, flags | O_NONBLOCK);*/

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

void try_make_ssl_connection(SSL_CTX *ssl_context, struct client_info *ci) {
    SSL *ssl_conn = SSL_new(ssl_context);

    if (!ssl_conn) {
        fprintf(stderr, "Failed creating new ssl connection %d", ci->client_id);
        return; // Just return prematurely
    }

    SSL_set_fd(ssl_conn, ci->socket);

    if (SSL_accept(ssl_conn) <= 0) {
        printf("ssl: ");
        ERR_print_errors_fp(stderr);
        printf("\n");

        SSL_shutdown(ssl_conn);
        SSL_free(ssl_conn);
        return;
    }

    ci->ssl_connection = ssl_conn;
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

    close(client->socket);
    fclose(client->dest_file);

    struct client_info **p = &client_pointer;
    *p = client->next;

    free(client);
    return;
}

int handle_upload(struct client_info *ci) {
    SSL *ssl = ci->ssl_connection;

    int bytes_received;
    if (ci->ssl_connection) {
        bytes_received = SSL_read(
            ssl, 
            ci->upload_buffer, 
            sizeof(ci->upload_buffer) //TODO: Consider making it sizeof(ci->upload_buffer) + 1
        );
    } else {
        bytes_received = recv(
            ci->socket,
            ci->upload_buffer,
            sizeof(ci->upload_buffer), 0 
        );
    }

    if (bytes_received < 1) {
        return -1;
    }

    printf("Received %d bytes from %s\n", bytes_received, ci->address_p);
    //ci->upload_buffer[bytes_received + 1] = 0; // TODO: uncomment this?

    if (!ci->dest_file) { // if file is uninitialized
        time_t time_var;
        time(&time_var);

        char filename[100];
        sprintf(filename, "%d_%s", ci->client_id, ctime(&time_var));
        
        FILE *new_file = fopen(filename, "w");
        if (!new_file) {
            fprintf(stderr, "Failed creating file");
            return -1;
        }
        ci->dest_file = new_file;
    }

    // Read from buffer to file
    int remaining = bytes_received;
    while(remaining > 0) {
        int bytes_written = fwrite(ci->upload_buffer, 1, bytes_received, ci->dest_file);
        if (fwrite < 0) {
            return -1;
        }
        remaining-=bytes_written;
    }

    return bytes_received;
}


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
                    int bytes_uploaded = handle_upload(client);
                    if (bytes_uploaded < 0) {
                        printf("->Disconnected from %s\n", client->address_p);
                        drop_client(client);
                        FD_CLR(i, &master);
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