# FILEDROP
A multiplexed Linux server for file uploads and downloads.

## Usage
- gcc -Wall filedrop.c -o filedrop -lssl -lcrypto && ./filedrop <bind_port> <storage_dir_path>

and then:

- gcc client.c -o client -lssl -lcrypto && ./client <server> <port> <true|false> <download|upload> <filename> <filepath>
