# Example: Spinning up the server instance.
# The arguments specify that the server is bound to 0.0.0.0:8080 and handles
# uploads and downloads to and from the directory `storage`. If this directory
# doesn't exist, it will be created. 

gcc -Wall filedrop.c -o filedrop -lssl -lcrypto && ./filedrop 8080 storage