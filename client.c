#include "filedrop.h"

/*
A simple client for filedrop that assumes a perfect interaction with no errors or retries.
*/

enum
{
    normal,
    use_ssl
};
enum
{
    upload,
    download
};

struct connection
{
    int type;
    FILE *target_file;
    char file_buffer[10240];
    int bytes_transferred;
    int socket;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
};

void shutdown_connection(struct connection *conn);
int read_from_server(struct connection *conn, char *buf, int buf_size);
int write_to_server(struct connection *conn, char *buf, int buf_size);
int upload_file_to_server(struct connection *conn, int *total_bytes_uploaded);
int download_file_from_server(struct connection *conn, int *total_bytes_downloaded);

// TODO: Add comprehensive display logic
int main(int argc, char *argv[])
{
    if (argc < 7)
    {
        fprintf(stderr, "Usage: client <host> <serv> <use_ssl> <action> <filename> <filepath>\n");
        exit(1);
    }

    char *hostname = argv[1];
    char *service = argv[2];
    char *use_ssl_input = argv[3];
    char *action_input = argv[4];
    char *filename = argv[5];
    char *filepath = argv[6];

    int connection_type;
    int action;

    if (strcmp(use_ssl_input, "true") == 0 || strcmp(use_ssl_input, "yes") == 0)
        connection_type = use_ssl;
    else if(strcmp(use_ssl_input, "false") == 0 || strcmp(use_ssl_input, "no") == 0)
        connection_type = normal;
    else  {
        fprintf(stderr, "Invalid use_ssl_input. Exiting..");
        exit(1);
    }

    if (strcmp(action_input, "upload") == 0 || strcmp(action_input, "-u") == 0)
        action = upload;
    else if (strcmp(action_input, "download") == 0 || strcmp(action_input, "-d") == 0)
        action = download;
    else
    {
        fprintf(stderr, "Invalid action. Exiting...\n");
        exit(1);
    }

    int access_r = access(filepath,F_OK);

    if (action == upload && access_r != 0) {
        fprintf(stderr, "Filepath %s does not exist\n", filepath);
        exit(1);
    } 

    if (action == download && access_r == 0) {
        fprintf(stderr, "Can't overwrite existing file %s\n", filepath);
        exit(1);
    }

    char *mode;
    if (action == upload)
        mode = "r";
    else
        mode = "w";

    FILE *target_file = fopen(filepath, mode);
    if (!target_file)
    {
        fprintf(stderr, "Couldn't open/create file %s. Exiting..\n", filename);
        exit(1);
    }

    printf("** Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *remote_address;
    if (getaddrinfo(hostname, service, &hints, &remote_address))
    {
        fprintf(stderr, "getaddrinfo() failed: (%s)", strerror(errno));
        exit(1);
    }

    char address_buffer[100];
    char service_buffer[100];
    if (getnameinfo(
            remote_address->ai_addr, remote_address->ai_addrlen,
            address_buffer, sizeof(address_buffer), service_buffer,
            sizeof(service_buffer), NI_NUMERICHOST | NI_NUMERICSERV))
        fprintf(stderr, "Couldn't get presentation name for remote: (%s).", strerror(errno));
    else
        printf("** Remote address is %s:%s\n", address_buffer, service_buffer);

    SOCKET remote = socket(remote_address->ai_family, remote_address->ai_socktype,
                           remote_address->ai_protocol);
    if (remote < 0)
    {
        fprintf(stderr, "socket() failed: (%s). Exiting...\n", strerror(errno));
        exit(1);
    }

    if (connect(remote, remote_address->ai_addr, remote_address->ai_addrlen))
    {
        fprintf(stderr, "Couldn't connect to server: (%s). Exiting..\n", strerror(errno));
        close(remote);
        freeaddrinfo(remote_address);
        exit(1);
    }
    freeaddrinfo(remote_address);
    printf("** Connection successful!\n");

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl_conn = NULL;

    if (connection_type == use_ssl)
    {
        printf("** Attempting SSL connection initiation.\n");
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx)
        {
            printf("** Couldn't create ssl context. Proceeding to fallback.\n");
            connection_type = normal;
        }
        else
        {
            ssl_conn = SSL_new(ssl_ctx);
            SSL_set_tlsext_host_name(ssl_conn, hostname);
            SSL_set_fd(ssl_conn, remote);

            if (SSL_connect(ssl_conn) == -1)
            {
                fprintf(stderr, "SSL_connect() failed: ");
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Exiting..");
                close(remote);
                SSL_CTX_free(ssl_ctx);
                exit(1);
            }

            printf("** SSL connection initiated. Using cipher suites: %s\n", SSL_get_cipher(ssl_conn));
        }
    }

    struct connection *conn = (struct connection *)calloc(1, sizeof(struct connection));
    memset(conn, 0, sizeof(conn));
    conn->type = connection_type;
    conn->socket = remote;
    conn->ssl = ssl_conn;
    conn->ssl_ctx = ssl_ctx;
    conn->target_file = target_file;

    int bytes_read;
    char recv_buffer[1024];

    if ((bytes_read = read_from_server(conn, recv_buffer, sizeof(recv_buffer))) < 1)
    {
        fprintf(stderr, "Failed read. Exiting...\n");
        exit(1);
    }
    printf("** Server: %.*s\n", bytes_read, recv_buffer);

    char *action_response = action == upload ? "u" : "d";
    if (write_to_server(conn, action_response, strlen(action_response)) < 0)
    {
        fprintf(stderr, "Failed write. Exiting...\n");
        shutdown_connection(conn);
        exit(1);
    }

    if ((bytes_read = read_from_server(conn, recv_buffer, sizeof(recv_buffer))) < 1)
    {
        fprintf(stderr, "Failed read. Exiting...\n");
        exit(1);
    }
    printf("** Server: %.*s\n", bytes_read, recv_buffer);

    char fname_response[1024];
    long bytes_to_upload;

    if (action == upload)
    {
        fseek(target_file, 0L, SEEK_END);
        bytes_to_upload = ftell(target_file);
        fseek(target_file, 0L, SEEK_SET);
        snprintf(fname_response, sizeof(fname_response), "{%ld}%s", bytes_to_upload, filename);
    }
    else
    {
        snprintf(fname_response, sizeof(fname_response), "%s", filename);
    }

    if (write_to_server(conn, fname_response, strlen(fname_response)) <= 0)
    {
        fprintf(stderr, "Failed write. Exiting...\n");
        shutdown_connection(conn);
        exit(1);
    }

    if ((bytes_read = read_from_server(conn, recv_buffer, sizeof(recv_buffer))) <= 0)
    {
        fprintf(stderr, "Failed read. Exiting...\n");
        shutdown_connection(conn);
        exit(1);
    }
    printf("** Server: %.*s\n", bytes_read, recv_buffer);

    int total_bytes = 0;
    if (action == upload)
    {
        if (upload_file_to_server(conn, &total_bytes) < 0)
        {
            printf("** Something went wrong during upload.\n");
        }
        printf("** Uploaded (%d) of (%lu) bytes\n", total_bytes, bytes_to_upload);
    }
    else if (action == download)
    {
        printf("Start download from server...\n");
        if (download_file_from_server(conn, &total_bytes) < 0) 
        {
            printf("** Something went wrong during download.\n");
        }
        printf("** Downloaded (%d) bytes from server to (%s). \n", total_bytes, filepath);
    }

    int last_bytes = read_from_server(conn, recv_buffer, sizeof(recv_buffer));
    if (last_bytes > 0)
        printf("** Server: %.*s\n", last_bytes, recv_buffer);

    shutdown_connection(conn);
}

void shutdown_connection(struct connection *conn)
{
    if (conn->ssl)
    {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->ssl_ctx)
        SSL_CTX_free(conn->ssl_ctx);

    shutdown(conn->socket, SHUT_RDWR);
    close(conn->socket);
}

int read_from_server(struct connection *conn, char *buf, int buf_size)
{
    int bytes_read;

    if (conn->type == use_ssl)
        bytes_read = SSL_read(conn->ssl, buf, buf_size);
    else
        bytes_read = recv(conn->socket, buf, buf_size, 0);

    printf("* Read %d bytes...\n", bytes_read);

    return bytes_read;
}

int write_to_server(struct connection *conn, char *buf, int buf_size)
{
    int bytes_sent;

    if (conn->type == use_ssl)
        bytes_sent = SSL_write(conn->ssl, buf, buf_size);
    else
        bytes_sent = send(conn->socket, buf, buf_size, 0);

    printf("* Sent %d bytes...\n", bytes_sent);

    return bytes_sent;
}

int upload_file_to_server(struct connection *conn, int *total_bytes_uploaded)
{
    while (1)
    {
        int bytes_read;
        if ((bytes_read = fread(
                 conn->file_buffer, 1, sizeof(conn->file_buffer), conn->target_file)) <= 0)
        {
            if (feof(conn->target_file) != 0)
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }

        int bytes_uploaded = 0;
        if ((bytes_uploaded = write_to_server(conn, conn->file_buffer, bytes_read)) <= 0)
            return -1;
        *total_bytes_uploaded += bytes_uploaded;
    }

    return 0;
}

int download_file_from_server(struct connection *conn, int *total_bytes_downloaded)
{
    while (1)
    {
        int bytes_read;
        if ((bytes_read = read_from_server(
                 conn, conn->file_buffer, sizeof(conn->file_buffer))) <= 0)
        {
            break;
        }

        int bytes_written = 0;
        while (bytes_written < bytes_read)
        {
            int bytes = fwrite(conn->file_buffer + bytes_written, 1, bytes_read - bytes_written, conn->target_file);
            if (bytes <= 0) return -1;
            bytes_written += bytes;
            *total_bytes_downloaded += bytes;
        }
    }

    return 0;
}

