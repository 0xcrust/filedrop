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
*   Check connection_info and remove redundant fields if any.
*   Find a way to get the file format or desired filename from the user.
*   Allow user to upload multiple files in one connection.
*   Create a unique folder for each user
*   Add proper commenting and some measure of documentation.
*   Write function prototypes in filedrop.h and move functions below
*   Check function return types
*   Clear redundant printfs
*   Write debug messages to a file
*   Sort out certificates.
*   Factor in FD_CLR to dropping a client
*/

// To list the contents of a directory: 
// https://stackoverflow.com/questions/4204666/how-to-list-files-in-a-directory-in-a-c-program

// TODO: This should be split into a `client` struct and a `upload` struct
// A client should be able to have multiple simultaneous uploads
struct connection {
    int state;
    struct sockaddr_storage address;
    socklen_t address_length;
    char address_p[NAME_LENGTH];
    int socket;
    int action;
    char f_buf[BUFFERSIZE];
    char f_name[F_NAME_LENGTH]; // string
    int bytes_transferred;
    SSL *ssl_conn;
    FILE *target_file;
    char next_msg[1024];
    struct connection *next;
};


static struct connection *active_connections = 0;

enum { upload, download };

// TODO!!!: Go back to normal way of serving uploads. At least for now
/*
enum {
    st_start, st_ssl_init_active, st_sent_action_prompt, st_rcvd_action_response,
    st_sent_fname_req, st_rcvd_filename, st_dl_active, st_ul_active,
    st_err, st_success
};*/

enum {
    send_action_prompt, ssl_handshake_in_progress, receive_action, send_fname_prompt,
    receive_fname, initiate_action, download_in_progress, upload_in_progress,
    error_state, action_success
};


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
struct connection *get_connection_info(SOCKET s) {
    struct connection *conn = active_connections;
    
    while(conn) {
        if (conn->socket == s) {
            printf("Found socket %d in active_clients list\n", s);
            printf("Location: %ld\n", (long) conn);
            return conn;
        }
        conn = conn->next;
    }

    return 0;
}

// TODO: Change API to return a number to represent error status and
// take in a pointer to the new connection instead
int *accept_connection(SOCKET server, struct connection *new_conn) {
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
        return -1;
    }
    // TODO: Is this redundant?
    if (get_connection_info(new_socket) != 0) {
        fprintf(stderr, "Socket in use by existing client\n");
        return -1; 
    }

    new_conn = (struct connection*) calloc(1, sizeof(struct connection));
    if (!new_conn) {
        fprintf(stderr, "Failed allocating memory for new client_info struct\n");
        return -1;
    }
    printf("new client created?\n");

    new_conn->state = send_action_prompt;
    new_conn->address = incoming_address;
    new_conn->address_length = incoming_address_len;
    new_conn->bytes_transferred = 0;
    // TODO: Handle possible errors
    getnameinfo(
        (struct sockaddr*) &new_conn->address, new_conn->address_length,
        new_conn->address_p, sizeof(new_conn->address_p), 0, 0,
        NI_NUMERICHOST
    );
    new_conn->address_length = sizeof(new_conn->address);
    new_conn->next = active_connections;
    new_conn->socket = new_socket;
    active_connections = new_conn;

    return 0;
}

// TODO: Move back into try_make_ssl_connection()-> Maybe not
int set_socket_non_blocking(int sock) {
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    if ((fcntl(sock, F_SETFL, flags | O_NONBLOCK)) < 0) {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

// TODO: Move back into try_make_ssl_connection() -> Maybe not
int set_socket_blocking(int sock) {
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        fprintf(stderr, "Set_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    if ((fcntl(sock, F_SETFL, flags ^ O_NONBLOCK)) < 0) {
        fprintf(stderr, "Set_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

int init_ssl_connection(SSL_CTX *ssl_context, struct connection* conn) {
    SSL *ssl_conn = SSL_new(ssl_context);

    if (!ssl_conn) {
        fprintf(stderr, "Failed creating new ssl connection");
        return -1;
    }

    SSL_set_fd(ssl_conn, conn->socket);
    return (set_socket_non_blocking(conn->socket));
}

int handle_ssl_connection(SSL_CTX *ssl_context, struct connection *conn) {
    int result = SSL_accept(conn->ssl_conn);
    printf("SSL_accept() read %d bytes\n", result);

    // TODO: Use another select call to block on a read here for a particular timeout?
    // The function takes in an argument that tells us whether we're reading
    // or writing

    fd_set writes;
    fd_set reads;

    // experiment with reducing this value
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    // TODO: Toggle reads_m and writes_m to include or exclude the fd based
    // on whether SSL wants a read or write?

    // Ideally shouldn't block since the outer select signalled that it can
    // already read or write
    int status = -1;
    while(1) {
        FD_ZERO(&writes);
        FD_ZERO(&reads);
        
        switch(SSL_get_error(conn->ssl_conn, result)) {
            case SSL_ERROR_NONE:
                status = 0;
                break;
            case SSL_ERROR_WANT_WRITE:
                status = 1;
                FD_SET(conn->socket, &writes);
                break;
            case SSL_ERROR_WANT_READ:
                status = 1;
                FD_SET(conn->socket, &reads);
                break;
            default:
                status = -1;
                break;
        }

        if (status < 1) break;

        if (select(conn->socket + 1, &reads, &writes, 0, &timeout) < 0) {
            fprintf(stderr, "handle_ssl_connection: Select() failed\n");
            status = -1;
            break;
        }
    }

    return status;
}

void drop_connection(struct connection *conn) {
    struct connection *cp = get_connection_info(conn->socket);
    if (cp == 0) {
        fprintf(stderr, "Client info does not exist for socket %d.\n", conn->socket);
        return;
    }

    if (conn->ssl_conn) {
        SSL_shutdown(conn->ssl_conn);
        SSL_free(conn->ssl_conn);
    }

    printf("closing socket %d\n", conn->socket);
    close(conn->socket);
    if (conn->target_file) fclose(conn->target_file);

    struct connection **p = &conn;
    *p = conn->next;
    if (cp == active_connections) {
        active_connections = cp->next;
    }
    free(cp);

    return;
}

int send_to_client(struct connection *conn, char *buf, int buf_size) {
    int bytes_sent;

    if(conn->ssl_conn) {
        bytes_sent = SSL_write(conn->ssl_conn, buf, buf_size);
    } else {
        bytes_sent = send(conn->socket, buf, buf_size, 0);
    }

    return bytes_sent;
}

int rec_send_to_client(struct connection *conn, char *buf, int buf_size) {
    int bytes_to_send = buf_size;
    int total_bytes_sent = 0;

    while(total_bytes_sent < bytes_to_send) {
        int bytes_sent;
        if ((bytes_sent = send_to_client(
            conn, (buf + total_bytes_sent), 
            (bytes_to_send - total_bytes_sent))) <= 0
        ) { 
            return -1; 
        } 

        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

int recv_from_client(struct connection *conn, char *buf, int buf_size) {
    int bytes_received;

    if(conn->ssl_conn) {
        bytes_received = SSL_write(conn->ssl_conn, buf, buf_size);
    } else {
        bytes_received = send(conn->socket, buf, buf_size, 0);
    }

    return bytes_received;
}

int rec_recv_from_client(struct connection *conn, char *buf, int buf_size, int *bytes_received) {
    int total_bytes_read = 0;

    while(1) {
        int bytes_read;
        if ((bytes_read = simple_recv(conn, buf + bytes_read, buf_size - bytes_read)) <= 0) {
            return bytes_read;
        } 
        *bytes_received+=bytes_read;
    }

    return 1; // For success
}

int handle_download(struct connection *conn, char *storage_dirname) {
    if (!conn->target_file) {
        char filepath[strlen(storage_dirname) + strlen(conn->f_name) + 1];
        snprintf(
            filepath, sizeof(filepath), "%s/%s", 
            storage_dirname, conn->f_name
        );
        printf("-> Opening file with name {%s}.\n", filepath);

        FILE *new_file = fopen(filepath, "w");
        if (!new_file) {
            fprintf(stderr, "Failed opening file.\n");
            return -1;
        }
        conn->target_file = new_file;
    }

    int bytes_read;
    if ((bytes_read = fread(conn->f_buf, 1, sizeof(conn->f_buf), conn->target_file)) <= 0) {
        if (feof(conn->target_file) != 0) {
            // File has finished sending
            return 0;
        } else {
            return -1;
        }
    }
    //fflush(conn->target_file);
    int result;
    if ((result = rec_send_to_client(conn, conn->f_buf, bytes_read)) > 0) 
    {
        conn->bytes_transferred+= result;
    }

    return result;
}

// TODO: On upload done, send EOF / shutdown to connection
// TODO: What to do here? Should it try to complete the upload by calling recursively
// or should it read what it can and move on
int handle_upload(struct connection *conn, char *storage_dirname) { 
    printf("Continuing upload...\n");
    if (!conn->target_file) { 
        char filepath[strlen(storage_dirname) + strlen(conn->f_name) + 1];
        snprintf(
            filepath, "%s/%s", 
            storage_dirname, conn->f_name
        );
        
        printf("-> Creating file with name {%.*s}.\n", sizeof(filepath), filepath);
        FILE *new_file = fopen(filepath, "w");
        if (!new_file) {
            fprintf(stderr, "Failed creating file.\n");
            return -1;
        }
        conn->target_file = new_file;
    }

    // TODO: Refactor this to use the read_from_client function
    int bytes_received;
    if (conn->ssl_conn) {
        bytes_received = SSL_read(
            conn->ssl_conn, 
            conn->f_buf, 
            sizeof(conn->f_buf)
        );
        if (bytes_received == -1) {
            fprintf(stderr, "-> SSL_read() failed: ");
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "\n");
            return -1;
        }
    } else {
        bytes_received = recv(
            conn->socket,
            conn->f_buf,
            sizeof(conn->f_buf), 0 
        );
        if (bytes_received == -1) {
            fprintf(stderr, "-> recv() failed: %s\n", strerror(errno));
            return -1;
        }
    }

    // TODO: Split handling of a failure from handling of a completed upload.
    // Don't return -1 for both

    printf("Received %d bytes from %s\n", bytes_received, conn->address_p);
    printf("Received: \n%.*s\n from stream", bytes_received, conn->f_buf);
    printf("Writing %d bytes to file.\n", bytes_received);

    char last = conn->f_buf[sizeof(conn->f_buf) - 1];
    printf("possible EOF char: %c\n", last);

    int remaining = bytes_received;
    while(remaining > 0) {
        int bytes_written = fwrite(conn->f_buf, 1, bytes_received, conn->target_file);
        printf("Wrote: \n%.*s\n to file", bytes_written, conn->f_buf);
        if (bytes_written < 0) {
            return -1;
        }
        remaining-=bytes_written;
    }
    fflush(conn->target_file); // needed?

    conn->bytes_transferred+=bytes_received;
    return bytes_received;
}

// TODO: Re-examine file permissions
int setup_storage(char *dirname) {
    struct stat sb;
    int res = stat(dirname, &sb);
    
    if (res < 0) {
        fprintf(stderr, "stat() error: %s\n", strerror(errno));
        return -1;
    }
    if (S_ISDIR(sb.st_mode))
    {
        // Storage already initialized
        return 0; 
    }

    // TODO: Handle situation where it already exists
    if (mkdir("storage", 755) != 0) { // TODO: examine permissions
        fprintf(
            stderr, 
            "Failed creating directory `storage` with permissions (755): %s\n",
            strerror(errno)
        );
        return -1; //error
    } 

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        //fprintf(stderr, "usage: filedrop <port_no>\n");
        fprintf(stderr, "Usage: filedrop <bind_port> <storage_dirname>");
        return 1;
    }
    
    char *port = argv[1];
    char *storage_dirname = argv[2];

    SSL_CTX *ssl_ctx;
    ssl_initialize(&ssl_ctx);

    printf("-> Configuring bind address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *local_address;
    getaddrinfo(INADDRANY, port, &hints, &local_address);

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

    setup_storage(storage_dirname);
    printf("-> Finished setting up storage folder!\n");

    fd_set reads_m;
    FD_ZERO(&reads_m);
    FD_SET(server, &reads_m);

    fd_set writes_m;
    FD_ZERO(&writes_m);
    int max_socket = server;

    printf("-> Starting loop to accept connections...\n");
    while(1) {
        fd_set reads = reads_m;
        fd_set writes = writes_m;
        printf("-> Server: Active and waiting to read or write\n");
        if (select(max_socket + 1, &reads, &writes, 0, 0) < 0) {
            fprintf(stderr, "select() call failed: %s\n", strerror(errno));
            return 1;
        }

        for (int i = 1; i <= max_socket; ++i) {
            if (FD_ISSET(i, &reads)) {
                if (i == server) {
                    printf("-> Server: New incoming connection.\n");
                    struct connection *new_conn;
                    if (accept_connection((SOCKET) i, new_conn) < 0) {
                        fprintf(stderr, "accept_connection() failed\n");
                        continue; 
                    }
                    printf("-> Server: New connection made from %s\n", new_conn->address_p);
                    FD_SET(new_conn->socket, &reads_m);
                    FD_SET(new_conn->socket, &writes_m);
                    if (new_conn->socket > max_socket) max_socket = new_conn->socket;
                    
                    if (init_ssl_connection(ssl_ctx, new_conn) > 0) {
                        printf("-> (%d): Initializing ssl connection attempt for socket\n", new_conn->socket);
                        new_conn->state = ssl_handshake_in_progress;
                    } else {
                        printf("-> (%d): Defaulting to non-TLS channel\n", new_conn->socket);
                        snprintf(
                            new_conn->next_msg, sizeof(new_conn->next_msg), "%s\n%s",
                            "Could not establish a TLS connection. Proceeding...",
                            "Do you want to upload or download a file? (U/u for upload. D/d for download): "
                        );
                        new_conn->state = send_action_prompt;
                    }
                } else {
                    printf("-> Server: Handling existing connection\n");
                    struct connection *conn = get_connection_info(i);
                    switch(conn->state) {
                        case ssl_handshake_in_progress: {
                            if (handle_ssl_connection(ssl_ctx, conn) < 0) {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Couldn't establish SSL connection. Defaulting to normal connection.\n"
                                );
                                conn->state = send_action_prompt;
                                break;
                            }
                            if (SSL_is_init_finished(conn->ssl_conn)) {
                                if (set_socket_blocking(conn->socket) < 0) {
                                    snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Connection exited: An error occured while initiating the SSL connection.\n"
                                    );
                                    conn->state = send_action_prompt;
                                    break;
                                }
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s\n%s",
                                    "TLS connection established successfully",
                                    "Do you want to upload or download a file? (U/u for upload. D/d for download): "
                                );
                                conn->state = send_action_prompt;
                                break;
                            } 
                        }

                        case receive_action: {
                            // TODO: Re-evaluate size
                            char read_buf[10]; 
                            int bytes_read;
                            if ((bytes_read = recv_from_client(conn, read_buf, sizeof(read_buf))) <= 0) {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s", "Connection Error. Exiting...\n"
                                );
                                conn->state = error_state;
                                break;
                            } else {
                                // TODO: More robust handling and parsing
                                char response = tolower(read_buf[0]); 
                                if (response == 'u') {
                                    conn->action = upload;
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "What should your upload be saved as?: "
                                    );
                                    conn->state = send_fname_prompt;
                                    break;
                                } else if (response == 'd') {
                                    conn->action = download;
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "What file do you want to download?: "
                                    );
                                    conn->state = send_fname_prompt;
                                    break;
                                } else {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "Invalid response, Please Enter (U/u)for uploads and (D/d) for downloads: "
                                    );
                                    conn->state = send_action_prompt;
                                    break;
                                }
                            }
                        }

                        case receive_fname: {
                            char read_buf[ sizeof(conn->f_name)]; 
                            int bytes_read;
                            // TODO: Check this
                            if ((bytes_read = recv_from_client(conn, read_buf, sizeof(read_buf) - 1)) <= 0) { 
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s", "Connection Error. Exiting...\n"
                                );
                                conn->state = error_state;
                                break;
                            } else {
                                read_buf[bytes_read] = 0; // TODO: Check this
                                int file_exists = access(read_buf, F_OK);
                                if (conn->action == upload) {
                                    if (file_exists == 0) {
                                        snprintf(
                                            conn->next_msg, sizeof(conn->next_msg), "%s",
                                            "File already exists. Please pick a unique name for your file: "
                                        );
                                        conn->state = send_fname_prompt;
                                        break;
                                    } else {
                                        snprintf(
                                            conn->next_msg, sizeof(conn->next_msg), "%s", "Starting upload.\n"
                                        );
                                    }
                                } else if (conn->action == download) {
                                    if (file_exists < 0) {
                                        snprintf(
                                            conn->next_msg, sizeof(conn->next_msg), "%s",
                                            "The file you requested doesn't exist.\n"
                                        );
                                        conn->state = send_fname_prompt;
                                        break;
                                    } else {
                                        snprintf(
                                            conn->next_msg, sizeof(conn->next_msg), "%s", "Starting download.\n"
                                        );
                                    }
                                }
                            }
                            snprintf(conn->f_name, sizeof(conn->f_name), "%s", read_buf);
                            conn->state = initiate_action;
                            break;
                        }

                        // Send progress during write?
                        case upload_in_progress: {
                            int res;
                            if ((res = handle_upload(conn, storage_dirname)) < 0) {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Error encountered during upload. Dropping connection...\n"
                                );
                                conn->state = error_state;
                            } else if (res == 0) {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), 
                                    "Upload of (%s) complete!. Bytes transferred: %d\n",
                                    conn->f_name, conn->bytes_transferred
                                );
                                conn->state = action_success;
                            } 
                            break;
                        }

                        default:
                            break;
                    }
                }
            } else if (FD_ISET(i, &writes)) {
                printf("(%d) is ready for writing..\n", i);
                struct connection *conn = get_connection_info(i);
                switch (conn->state) {
                    case send_action_prompt: {
                        if (send_to_client(conn, conn->next_msg, sizeof(conn->next_msg)) < 0) {
                            sprintf(conn->next_msg, sizeof(conn->next_msg), "Connection Error. Dropping client");
                            conn->state = error_state;
                            break;
                        } 
                        conn->state = receive_action;
                        break;
                    }

                    case ssl_handshake_in_progress: {
                        if (handle_ssl_connection(ssl_ctx, conn) < 0) {
                            snprintf(
                                conn->next_msg, sizeof(conn->next_msg), "%s",
                                "Couldn't establish SSL connection. Defaulting to normal connection.\n"
                            );
                            conn->state = send_action_prompt;
                            break;
                        }
                        if (SSL_is_init_finished(conn->ssl_conn)) {
                            if (set_socket_blocking(conn->socket) < 0) {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Connection exited: An error occured while initiating the SSL connection.\n"
                                );
                                conn->state = error_state;
                                break;
                            }
                            snprintf(
                                conn->next_msg, sizeof(conn->next_msg), "%s\n%s",
                                "TLS connection established successfully",
                                "Do you want to upload or download a file? (U/u for upload. D/d for download): "
                            );
                            conn->state = send_action_prompt;
                            break;
                        }
                    }

                    case send_fname_prompt: {
                        if (send_to_client(conn, conn->next_msg, sizeof(conn->next_msg)) <= 0) {
                            sprintf(conn->next_msg, sizeof(conn->next_msg), "Connection Error. Dropping client");
                            conn->state = error_state;
                            break;
                        }

                        conn->state = receive_fname;
                        break;
                    }

                    case initiate_action: {
                        if (send_to_client(conn, conn->next_msg, sizeof(conn->next_msg)) <= 0) {
                            sprintf(
                                conn->next_msg, sizeof(conn->next_msg), 
                                "Connection Error. Dropping client"
                            );
                            conn->state = error_state;
                            break;
                        }

                        conn->state = conn->action == upload ? upload_in_progress : download_in_progress;

                        break;
                    }

                    case download_in_progress: {
                        int res;
                        if ((res = handle_download(conn, storage_dirname)) == -1) {
                            sprintf(
                                conn->next_msg, sizeof(conn->next_msg), 
                                "Error while serving download. Dropping client"
                            );
                            conn->state = error_state;
                        } else if (res == 0) {
                            conn->state = action_success;
                        } 
                        break;
                    }

                    case action_success: {
                        if (send_to_client(conn, conn->next_msg, strlen(conn->next_msg)) <= 0) {   
                            conn->state = error_state;
                            break;
                        }
                        drop_connection(conn);
                        break;
                    }

                    case error_state: {
                        send_to_client(conn, conn->next_msg, strlen(conn->next_msg));
                        drop_connection(conn);
                        break;
                    }
                }
            }
        }
    }

    printf("Shutting down server...\n");
    struct connection *conn = active_connections;
    while(conn) {
        struct client_info *next = conn->next;
        drop_connection(conn);
        conn = next;
    }
    close(server);
    SSL_CTX_free(ssl_ctx);
}