#include "filedrop.h"

/*
Filedrop is a server for fast file uploads and requests.

Features:
    * Supports multiple concurrent uploads and downloads.
    * Supports transfers up to 2GB.
    * Supports SSL connections.
*/

// TODO: Find out why ssl connections may break
struct connection
{
    int state;
    struct sockaddr_storage address;
    socklen_t address_length;
    char address_p[NAME_LENGTH];
    int socket;
    int action;
    char f_buf[BUFFERSIZE];
    char f_name[F_NAME_LENGTH];
    int exp_bytes_transferred;
    int bytes_transferred;
    SSL *ssl_conn;
    FILE *target_file;
    char next_msg[1024];
    long last_active;
    struct connection *next;
};

static struct connection *active_connections = 0;

enum
{
    upload,
    download
};

enum
{
    send_action_prompt,
    receive_action,
    send_fname_prompt,
    receive_fname,
    initiate_action,
    download_in_progress,
    upload_in_progress,
    fail_state,
    action_success
};

void init_openSSL(SSL_CTX **ssl_context);
int setup_storage(char *dirname);
struct connection *get_connection_info(SOCKET s);
int accept_connection(SOCKET server, struct connection **conn_p);
int set_socket_non_blocking(int sock);
int init_ssl_connection(SSL_CTX *ssl_context, struct connection *conn);
void drop_connection(struct connection *conn);
int send_to_client(struct connection *conn, char *buf, int buf_size);
int receive_from_client(struct connection *conn, char *buf, int buf_size);
int handle_client_download(struct connection *conn, char *storage_dirname);
int handle_client_upload(struct connection *conn, char *storage_dirname);
int parse_upload_fname_response(char *response, char **fb, char **lb, char **fname, char **err_msg);
int parse_filename(char **input, char **err_msg);
char *print_state(int state);

long get_time()
{
    time_t t;
    time(&t);
    return (long)t;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        fprintf(stderr, "Usage: filedrop <bind_port> <storage_dirname>\n");
        return 1;
    }

    char *port = argv[1];
    char *storage_dirname = argv[2];

    SSL_CTX *ssl_ctx;
    init_openSSL(&ssl_ctx);

    printf("** Configuring bind address..\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *local_address;
    getaddrinfo(INADDRANY, port, &hints, &local_address);

    printf("** Creating socket..\n");
    int server;
    server = socket(
        local_address->ai_family,
        local_address->ai_socktype,
        local_address->ai_protocol);

    if (server < 0)
    {
        fprintf(stderr, "socket() call failed: %s", strerror(errno));
        return 1;
    }

    printf("** Binding socket to port %s..\n", argv[1]);
    if (bind(server, local_address->ai_addr, local_address->ai_addrlen))
    {
        fprintf(stderr, "bind() call failed: %s\n", strerror(errno));
        return 1;
    }
    freeaddrinfo(local_address);

    if (listen(server, BACKLOG) != 0)
    {
        fprintf(stderr, "listen() call failed: %s\n", strerror(errno));
        return 1;
    }
    printf("** Active and listening with a queue limit of %d.\n", BACKLOG);

    if (setup_storage(storage_dirname) < 0)
        return 1;
    printf("** Completed storage setup.\n");
    strcat(storage_dirname, "/");

    fd_set reads_m;
    FD_ZERO(&reads_m);
    FD_SET(server, &reads_m);

    fd_set writes_m;
    FD_ZERO(&writes_m);
    int max_socket = server;

    printf("** Starting up..\n");
    long last_check = get_time();
    while (1)
    {
        fd_set reads = reads_m;
        fd_set writes = writes_m;
        printf("** Blocking on select..\n");
        if (select(max_socket + 1, &reads, &writes, 0, 0) < 0)
        {
            fprintf(stderr, "select() call failed: %s\n", strerror(errno));
            return 1;
        }

        for (int i = 1; i <= max_socket; ++i)
        {
            if (FD_ISSET(i, &reads))
            {
                if (i == server)
                {
                    struct connection *new_conn;
                    if (accept_connection((SOCKET)i, &new_conn) < 0)
                    {
                        fprintf(stderr, "accept_connection() failed\n");
                        if (new_conn)
                            drop_connection(new_conn);
                        continue;
                    }
                    printf("** New connection made from %.*s with socket %d.\n", (int)sizeof(new_conn->address_p), new_conn->address_p, new_conn->socket);
                    FD_SET(new_conn->socket, &writes_m);
                    if (new_conn->socket > max_socket)
                        max_socket = new_conn->socket;

                    if (init_ssl_connection(ssl_ctx, new_conn) < 0)
                    {
                        printf("(%d): Defaulting to non-TLS channel.\n", new_conn->socket);
                        snprintf(
                            new_conn->next_msg, sizeof(new_conn->next_msg),
                            "Could not establish a TLS connection. Proceeding...\nDo you want to upload or download a file? (U/u for upload. D/d for download): ");
                        SSL_shutdown(new_conn->ssl_conn);
                        SSL_free(new_conn->ssl_conn);
                        new_conn->ssl_conn = 0;
                    }
                    else
                    {
                        printf("(%d): TLS connection successful with cipher %s.\n", new_conn->socket, SSL_get_cipher(new_conn->ssl_conn));
                        snprintf(
                            new_conn->next_msg, sizeof(new_conn->next_msg),
                            "TLS connection successful. Do you want to upload or download a file? (U/u for upload, D/d for download): ");
                    }
                    new_conn->state = send_action_prompt;
                    FD_SET(new_conn->socket, &writes_m);
                }
                else
                {
                    struct connection *conn = get_connection_info(i);
                    conn->last_active = get_time();
                    memset(conn->next_msg, 0, sizeof(conn->next_msg));
                    printf("(%d): Available for read with state (%s)..\n", i, print_state(conn->state));
                    switch (conn->state)
                    {
                    case receive_action:
                    {
                        char read_buf[100];
                        int bytes_read;
                        if ((bytes_read = receive_from_client(conn, read_buf, sizeof(read_buf))) <= 0)
                        {
                            FD_CLR(conn->socket, &reads_m);
                            printf("(%d): Error. Connection dropped.\n", conn->socket);
                            drop_connection(conn);
                            break;
                        }
                        else
                        {
                            read_buf[bytes_read] = 0;
                            char *response = read_buf;
                            while (isspace(*read_buf))
                                response++;
                            char response_l = tolower(response[0]);

                            if (response_l == 'u')
                            {
                                conn->action = upload;
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Specify upload size in bytes and the name it should be saved as?\nExample: {2345}example.txt: ");
                                conn->state = send_fname_prompt;
                                FD_CLR(conn->socket, &reads_m);
                                FD_SET(conn->socket, &writes_m);
                                break;
                            }
                            else if (response_l == 'd')
                            {
                                conn->action = download;
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "What file do you want to download?: ");
                                conn->state = send_fname_prompt;
                                FD_CLR(conn->socket, &reads_m);
                                FD_SET(conn->socket, &writes_m);
                                break;
                            }
                            else
                            {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s",
                                    "Invalid response, Please Enter (U/u)for uploads and (D/d) for downloads: ");
                                conn->state = send_action_prompt;
                                FD_CLR(conn->socket, &reads_m);
                                FD_SET(conn->socket, &writes_m);
                                break;
                            }
                        }
                    }

                    case receive_fname:
                    {
                        char response[sizeof(conn->f_name)];
                        int bytes_read;
                        if ((bytes_read = receive_from_client(conn, response, sizeof(response) - 1)) <= 0)
                        {
                            FD_CLR(conn->socket, &reads_m);
                            printf("(%d): Error. Connection dropped.\n", conn->socket);
                            drop_connection(conn);
                            break;
                        }
                        else
                        {
                            response[bytes_read] = 0;
                            char *filename = response;
                            int exp_size;
                            char *err_msg;

                            if (conn->action == upload)
                            {
                                char *fb;
                                char *lb;
                                if ((parse_upload_fname_response(response, &fb, &lb, &filename, &err_msg)) < 0)
                                {
                                    snprintf(conn->next_msg, sizeof(conn->next_msg), "%s%s", err_msg, "Please retry with the format {<bytes>}<filename>.\n:-> ");
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }

                                int found_invalid = 0;
                                char *p = fb + 1;

                                while (p != lb)
                                {
                                    if (!isdigit(*p))
                                    {
                                        found_invalid = 1;
                                        break;
                                    }
                                    p++;
                                }

                                errno = 0;
                                *lb = 0;
                                long exp_size_l = strtol(fb + 1, &lb, 10);

                                if (found_invalid == 1 || errno != 0 || lb == 0)
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "Failed parsing input bytes. Please retry with format {<bytes>}<filename>: ");
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }

                                if (exp_size_l == 0)
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "Can't upload 0 bytes of data. Please retry: ");
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }

                                if (exp_size_l > (long)INT_MAX)
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "Upload file size exceeds 2GB limit: Please retry: ");
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }
                                exp_size = exp_size_l;
                            }

                            if ((parse_filename(&filename, &err_msg)) < 0)
                            {
                                snprintf(
                                    conn->next_msg, sizeof(conn->next_msg), "%s:%s %s: ",
                                    "Invalid filename", err_msg, "Please retry with a valid name: ");
                                conn->state = send_fname_prompt;
                                FD_CLR(conn->socket, &reads_m);
                                FD_SET(conn->socket, &writes_m);
                                break;
                            }

                            snprintf(conn->f_name, sizeof(conn->f_name), "%s", filename);
                            char filepath[100];
                            snprintf(filepath, sizeof(filepath), "%s%s", storage_dirname, filename);
                            int file_exists = access(filepath, F_OK);
                            if (conn->action == upload)
                            {
                                if (file_exists == 0)
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg),
                                        "File %s already exists. Please pick a unique name for your file: ",
                                        filename);
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }
                                else
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s", "Starting upload..\n");
                                    conn->exp_bytes_transferred = exp_size;
                                }
                            }
                            else if (conn->action == download)
                            {
                                if (file_exists < 0)
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s",
                                        "The file you requested doesn't exist. Please make another request: ");
                                    conn->state = send_fname_prompt;
                                    FD_CLR(conn->socket, &reads_m);
                                    FD_SET(conn->socket, &writes_m);
                                    break;
                                }
                                else
                                {
                                    snprintf(
                                        conn->next_msg, sizeof(conn->next_msg), "%s", "Starting download..\n");
                                }
                            }
                        }
                        conn->state = initiate_action;
                        FD_CLR(conn->socket, &reads_m);
                        FD_SET(conn->socket, &writes_m);
                        break;
                    }

                    case upload_in_progress:
                    {
                        int res = handle_client_upload(conn, storage_dirname);
                        if (res != -1 && conn->bytes_transferred == conn->exp_bytes_transferred)
                        {
                            printf("(%d): Upload complete! Transferred (%d) of (%d) bytes.\n", conn->socket, conn->bytes_transferred, conn->exp_bytes_transferred);
                            snprintf(
                                conn->next_msg, sizeof(conn->next_msg),
                                "Upload of (%s) complete!. Bytes transferred: %d\n",
                                conn->f_name, conn->bytes_transferred);
                            conn->state = action_success;
                            FD_CLR(conn->socket, &reads_m);
                            FD_SET(conn->socket, &writes_m);
                            break;
                        }

                        char path[200];
                        snprintf(path, sizeof(path), "%s%s", storage_dirname, conn->f_name);
                        if (res == -2)
                        {
                            snprintf(
                                conn->next_msg, sizeof(conn->next_msg), "%s",
                                "Internal Error encountered during upload. Dropping connection..\n");
                            printf("(%d): Upload failed. Deleting incomplete file (%s) and dropping..\n", conn->socket, path);
                            unlink(path);
                            conn->state = fail_state;
                            FD_CLR(conn->socket, &reads_m);
                            FD_SET(conn->socket, &writes_m);
                            break;
                        }

                        if (res <= 0)
                        {
                            FD_CLR(conn->socket, &reads_m);
                            printf("(%d): Upload failed. Deleting incomplete file (%s) and dropping..\n", conn->socket, path);
                            unlink(path);
                            drop_connection(conn);
                        }
                        break;
                    }

                    default:
                        break;
                    }
                }
            }
            else if (FD_ISSET(i, &writes))
            {
                struct connection *conn = get_connection_info(i);
                conn->last_active = get_time();
                printf("(%d): Ready for writing with state (%s)\n", conn->socket, print_state(conn->state));
                switch (conn->state)
                {
                case send_action_prompt:
                {
                    if (send_to_client(conn, conn->next_msg, strlen(conn->next_msg)) < 0)
                    {
                        FD_CLR(conn->socket, &writes_m);
                        printf("(%d): Error. Connection dropped.\n", conn->socket);
                        drop_connection(conn);
                        break;
                    }
                    conn->state = receive_action;
                    FD_CLR(conn->socket, &writes_m);
                    FD_SET(conn->socket, &reads_m);
                    break;
                }

                case send_fname_prompt:
                {
                    if (send_to_client(conn, conn->next_msg, strlen(conn->next_msg)) <= 0)
                    {
                        printf("Error. Couldn't send fname prompt to client.\n");
                        FD_CLR(conn->socket, &writes_m);
                        printf("(%d): Error. Connection dropped.\n", conn->socket);
                        drop_connection(conn);
                        break;
                    }

                    conn->state = receive_fname;
                    FD_CLR(conn->socket, &writes_m);
                    FD_SET(conn->socket, &reads_m);
                    break;
                }

                case initiate_action:
                {
                    if (send_to_client(conn, conn->next_msg, strlen(conn->next_msg)) <= 0)
                    {
                        FD_CLR(conn->socket, &writes_m);
                        printf("(%d): Error. Connection dropped.\n", conn->socket);
                        drop_connection(conn);
                        break;
                    }

                    if (conn->action == upload)
                    {
                        conn->state = upload_in_progress;
                        FD_CLR(conn->socket, &writes_m);
                        FD_SET(conn->socket, &reads_m);
                    }
                    else
                    {
                        conn->state = download_in_progress;
                    }

                    break;
                }

                case download_in_progress:
                {
                    memset(conn->next_msg, 0, sizeof(conn->next_msg));
                    int res = handle_client_download(conn, storage_dirname);

                    if (conn->bytes_transferred == conn->exp_bytes_transferred)
                    {
                        if (res == -1)
                        {
                            FD_CLR(conn->socket, &writes_m);
                            printf("(%d): Error. Connection dropped.\n", conn->socket);
                            drop_connection(conn);
                            break;
                        }
                        else
                        {
                            printf("(%d): Upload complete! Transferred (%d) of (%d) bytes.\n", conn->socket, conn->bytes_transferred, conn->exp_bytes_transferred);
                            snprintf(
                                conn->next_msg, sizeof(conn->next_msg),
                                "Download of (%s) complete!. Bytes transferred: %d\n",
                                conn->f_name, conn->bytes_transferred);
                            conn->state = action_success;
                            break;
                        }
                    }

                    if (res == -2)
                    {
                        printf("(%d): Error. Going to fail state..\n", conn->socket);
                        snprintf(
                            conn->next_msg, sizeof(conn->next_msg),
                            "Error while serving download. Dropping client");
                        conn->state = fail_state;
                        break;
                    }

                    if (res <= 0)
                    {
                        FD_CLR(conn->socket, &writes_m);
                        printf("(%d): Error. Connection dropped.\n", conn->socket);
                        drop_connection(conn);
                        break;
                    }

                    break;
                }

                case action_success:
                {
                    send_to_client(conn, conn->next_msg, strlen(conn->next_msg));
                    FD_CLR(conn->socket, &writes_m);
                    FD_CLR(conn->socket, &reads_m);
                    printf("(%d): Connection dropped.\n", conn->socket);
                    drop_connection(conn);
                    break;
                }

                case fail_state:
                {
                    send_to_client(conn, conn->next_msg, strlen(conn->next_msg));
                    FD_CLR(conn->socket, &writes_m);
                    FD_CLR(conn->socket, &reads_m);
                    printf("(%d): Connection dropped.\n", conn->socket);
                    drop_connection(conn);
                    break;
                }
                }
            }
        }

        // Do a health check and drop faulty connections
        int duration = (5 * 60);
        // int duration = 20;
        long current_time = get_time();

        if ((current_time - last_check) > duration)
        {
            struct connection *p = active_connections;
            while (p)
            {
                struct connection *next = p->next;
                if ((current_time - p->last_active) > duration)
                {
                    printf("(%d): Connection dropped for inactivity.\n", p->socket);
                    FD_CLR(p->socket, &reads_m);
                    FD_CLR(p->socket, &writes_m);
                }
                p = next;
            }
        }
    }

    printf("** Server shutting down..\n");
    struct connection *conn = active_connections;
    while (conn)
    {
        struct connection *next = conn->next; // TODO: CHECKME
        printf("(%d): Connection dropped.\n", conn->socket);
        drop_connection(conn);
        conn = next;
    }
    close(server);
    SSL_CTX_free(ssl_ctx);
}

// Initialize and setup openSSL context
void init_openSSL(SSL_CTX **ssl_context)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx)
    {
        fprintf(stderr, "Failed creating SSL context.\n");
        exit(1);
    }

    if (!SSL_CTX_use_certificate_file(ssl_ctx, "cert/cert.pem", SSL_FILETYPE_PEM) || !SSL_CTX_use_PrivateKey_file(ssl_ctx, "cert/key.pem", SSL_FILETYPE_PEM))
    {
        fprintf(stderr, "Missing one or both files for ssl credentials.\n");
        SSL_CTX_free(ssl_ctx);
        exit(1);
    }

    *ssl_context = ssl_ctx;
    printf("** SSL initialized.\n");
}

// Find the client_info for a particular socket s
struct connection *get_connection_info(SOCKET s)
{
    struct connection *conn = active_connections;

    while (conn)
    {
        if (conn->socket == s)
            return conn;
        conn = conn->next;
    }

    return 0;
}

// Accept a new socket and create a connection struct for it
int accept_connection(SOCKET server, struct connection **conn_p)
{
    struct sockaddr_storage incoming_address;
    socklen_t incoming_address_len = sizeof(incoming_address);

    int new_socket = accept(
        server,
        (struct sockaddr *)&incoming_address,
        &incoming_address_len);

    if (new_socket < 0)
    {
        fprintf(stderr, "Call to accept() failed: %s\n", strerror(errno));
        return -1;
    }

    if (set_socket_non_blocking(new_socket) < 0)
    {
        fprintf(stderr, "Failed to set socket to non-blocking...\n");
        return -1;
    }

    if (get_connection_info(new_socket) != 0)
    {
        fprintf(stderr, "Socket in use by existing client\n");
        return -1;
    }

    struct connection *new_conn = (struct connection *)calloc(1, sizeof(struct connection));
    if (!new_conn)
    {
        fprintf(stderr, "Failed allocating memory for new client_info struct\n");
        return -1;
    }

    new_conn->state = send_action_prompt;
    new_conn->address = incoming_address;
    new_conn->address_length = incoming_address_len;
    new_conn->bytes_transferred = 0;
    new_conn->exp_bytes_transferred = 0;
    new_conn->last_active = get_time();
    if (getnameinfo(
            (struct sockaddr *)&new_conn->address, new_conn->address_length,
            new_conn->address_p, sizeof(new_conn->address_p), 0, 0,
            NI_NUMERICHOST) != 0)
    {
        return -1;
    }
    new_conn->next = active_connections;
    new_conn->socket = new_socket;
    active_connections = new_conn;

    *conn_p = new_conn;
    return 0;
}

int set_socket_non_blocking(int sock)
{
    int flags;
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
    {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    if ((fcntl(sock, F_SETFL, flags | O_NONBLOCK)) < 0)
    {
        fprintf(stderr, "Set_non_blocking. fcntl() call failed: (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

int init_ssl_connection(SSL_CTX *ssl_context, struct connection *conn)
{
    SSL *ssl_conn = SSL_new(ssl_context);

    if (!ssl_conn)
    {
        fprintf(stderr, "Failed creating new ssl connection");
        return -1;
    }

    SSL_set_fd(ssl_conn, conn->socket);
    conn->ssl_conn = ssl_conn;

    fd_set writes;
    fd_set reads;

    int status = -1;

    struct timeval timeout;

    do
    {
        FD_ZERO(&writes);
        FD_ZERO(&reads);

        timeout.tv_sec = 0;
        timeout.tv_usec = 200;

        status = SSL_accept(conn->ssl_conn);

        switch (SSL_get_error(conn->ssl_conn, status))
        {
        case SSL_ERROR_NONE:
            status = 0;
            printf("ssl_error_none\n");
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

        if (status == 1)
        {
            if (select(conn->socket + 1, &reads, &writes, 0, &timeout) >= 1)
            {
                status = 1;
            }
            else
            {
                fprintf(stderr, "(%d): Handle_ssl_connection: Select() failed\n", conn->socket);
                status = -1;
            }
        }

    } while (!SSL_is_init_finished(conn->ssl_conn) && status == 1);

    return status;
}

void drop_connection(struct connection *conn)
{
    struct connection *cp = get_connection_info(conn->socket);
    if (cp == 0)
    {
        fprintf(stderr, "Client info does not exist for socket %d.\n", conn->socket);
        return;
    }

    if (conn->ssl_conn)
    {
        SSL_shutdown(conn->ssl_conn);
        SSL_free(conn->ssl_conn);
    }

    shutdown(conn->socket, SHUT_RD | SHUT_WR);
    close(conn->socket);
    if (conn->target_file)
        fclose(conn->target_file);

    struct connection **p = &conn;
    *p = conn->next;
    if (cp == active_connections)
    {
        active_connections = cp->next;
    }
    free(cp);

    return;
}

int send_to_client(struct connection *conn, char *buf, int buf_size)
{
    int total_bytes_sent = 0;

    while (1)
    {
        int bytes_sent;

        if (conn->ssl_conn)
            bytes_sent = SSL_write(
                conn->ssl_conn,
                buf + total_bytes_sent,
                buf_size - total_bytes_sent);
        else
            bytes_sent = send(
                conn->socket,
                buf + total_bytes_sent,
                buf_size - total_bytes_sent, 0);

        if (bytes_sent <= 0)
            break;
        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

int receive_from_client(struct connection *conn, char *buf, int buf_size)
{
    int total_bytes_received = 0;

    while (1)
    {
        int bytes_read;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(conn->socket, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 200;

        if (select(conn->socket + 1, &read_fds, 0, 0, &timeout) <= 0)
            break;

        if (conn->ssl_conn)
            bytes_read = SSL_read(
                conn->ssl_conn,
                buf + total_bytes_received,
                buf_size - total_bytes_received);
        else
            bytes_read = recv(
                conn->socket,
                buf + total_bytes_received,
                buf_size - total_bytes_received, 0);

        if (bytes_read <= 0)
            break;

        total_bytes_received += bytes_read;
    }

    return total_bytes_received;
}

int handle_client_download(struct connection *conn, char *storage_dirname)
{
    char path[sizeof(storage_dirname) + sizeof(conn->f_name)];
    snprintf(path, sizeof(path), "%s%s", storage_dirname, conn->f_name);

    if (!conn->target_file)
    {
        printf("(%d): Starting download of %s..\n", conn->socket, conn->f_name);

        FILE *new_file = fopen(path, "r");
        if (!new_file)
        {
            fprintf(stderr, "Failed opening target file for download.\n");
            return -2;
        }
        conn->target_file = new_file;

        fseek(conn->target_file, 0L, SEEK_END);
        conn->exp_bytes_transferred = ftell(conn->target_file);
        fseek(conn->target_file, 0L, SEEK_SET);
    }

    int bytes_read;
    if ((bytes_read = fread(conn->f_buf, 1, sizeof(conn->f_buf), conn->target_file)) <= 0)
    {
        if (feof(conn->target_file) != 0)
        {
            return 0;
        }
        else
        {
            return -2;
        }
    }

    int bytes_sent;
    if ((bytes_sent = send_to_client(conn, conn->f_buf, bytes_read)) <= 0)
    {
        return -1;
    }

    conn->bytes_transferred += bytes_sent;
    return bytes_sent;
}

// Returns 0 for okay, -2 for internal errors
int handle_client_upload(struct connection *conn, char *storage_dirname)
{
    char path[sizeof(storage_dirname) + sizeof(conn->f_name)];
    snprintf(path, sizeof(path), "%s%s", storage_dirname, conn->f_name);

    if (!conn->target_file)
    {
        printf("(%d): Starting upload of %s..\n", conn->socket, conn->f_name);

        FILE *new_file = fopen(path, "w");
        if (!new_file)
        {
            fprintf(stderr, "Failed creating file for upload.\n");
            return -2;
        }
        conn->target_file = new_file;
    }

    int bytes_received;
    if ((bytes_received = receive_from_client(conn, conn->f_buf, sizeof(conn->f_buf))) <= 0)
    {
        return bytes_received;
    }

    if (conn->bytes_transferred + bytes_received >= conn->exp_bytes_transferred)
    {
        bytes_received = conn->exp_bytes_transferred - conn->bytes_transferred;
    }
    if (bytes_received == 0)
        return 0;

    int bytes_written = 0;
    while (bytes_written < bytes_received)
    {
        int bytes = fwrite(conn->f_buf + bytes_written, 1, bytes_received - bytes_written, conn->target_file);
        if (bytes <= 0)
        {
            return -2;
        }
        bytes_written += bytes;
        conn->bytes_transferred += bytes;

        fflush(conn->target_file);
    }

    return bytes_received;
}

int setup_storage(char *dirname)
{
    struct stat sb;
    if (stat(dirname, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return 0;
    }

    if (mkdir(dirname, 755) != 0)
    { // TODO: examine permissions
        fprintf(
            stderr,
            "Failed creating directory `storage` with permissions (755): %s\n",
            strerror(errno));
        return -1;
    }

    return 0;
}

// Parses input for '{file_size}filename'
int parse_upload_fname_response(char *response, char **fb, char **lb, char **fname, char **err_msg)
{
    char *first_bracket;
    char *last_bracket;

    if ((first_bracket = strstr(response, "{")) == 0)
    {
        *err_msg = "Invalid response. Couldn't find '{'. ";
        return -1;
    }

    if ((last_bracket = strstr(first_bracket, "}")) == 0)
    {
        *err_msg = "Invalid response. Couldn't find '}' after '{'. ";
        return -1;
    }

    char *filename = last_bracket + 1;
    if (!filename)
    {
        *err_msg = "Missing filename. \n";
        return -1;
    }

    *fb = first_bracket;
    *lb = last_bracket;
    *fname = filename;

    return 0;
}

int parse_filename(char **input, char **err_msg)
{
    char *start = *input;
    char *end = *input;

    while (isspace(*start))
    {
        start++;
    }

    while (*end != 0)
        end++;

    while (end > start && (isspace(*(end - 1)) || *(end - 1) == '\n'))
    {
        end--;
    }
    *end = 0;

    if (start == end)
    {
        *err_msg = "Filename is empty. ";
        return -1;
    }

    if (!start)
    {
        *err_msg = "Invalid filename. ";
        return -1;
    }

    for (int i = 0; start[i] != '\0'; i++)
    { // is this valid?
        if (start[i] == '/' || start[i] == '\n' || start[i] == '\r' || start[i] == '\t')
        {
            *err_msg = "Invalid character in filename. ";
            return -1;
        }
    }

    const char *valid_ext[] = {
        ".txt", ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".csv", ".jpg",
        ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wmv", ".flv",
        ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".tgz", ".dmg", ".iso", ".exe", ".msi",
        ".deb", ".rpm", ".sh", ".c", ".cpp", ".h", ".hpp", ".py", ".java", ".php", ".html",
        ".css", ".js", ".xml", ".json", ".md", ".ipynb", ".r", ".rmd", ".tex", ".sql", ".yml",
        ".yaml", ".ini", ".cfg", ".conf", ".log", ".bak", ".tmp", ".swp"};

    int num_ext = sizeof(valid_ext) / sizeof(valid_ext[0]);
    int valid = 0;

    char *ext = strrchr(start, '.');

    if (ext != NULL)
    {
        for (int i = 0; i < num_ext; i++)
        {
            if (strcmp(ext, valid_ext[i]) == 0)
            {
                valid = 1;
                break;
            }
        }
    }
    else
        valid = 1;

    if (!valid)
    {
        *err_msg = "Invalid filename extension. ";
        return -1;
    }

    *input = start;
    return 0;
}

char *print_state(int state)
{
    switch (state)
    {
    case 0:
        return "send_action_prompt";
    case 1:
        return "receive_action";
    case 2:
        return "send_fname_prompt";
    case 3:
        return "receive_fname";
    case 4:
        return "initiate_action";
    case 5:
        return "download_in_progress";
    case 6:
        return "upload_in_progress";
    case 7:
        return "fail_state";
    case 8:
        return "action_success";
    default:
        return "";
    }
}