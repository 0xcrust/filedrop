# Example: Uploading to the server.
# Connecting to the server running at 0:8080 via SSL and uploading 
# the file at location `./mydir/videos/saved.mp4` to the server to be saved as 
# client.mp4. Currently this will fail to be uploaded if a file by the same name
# already exists in the server's storage.

gcc client.c -o client -lssl -lcrypto && ./client 0 8080 true upload client.mp4 ./mydir/videos/saved.mp4

# Example: Downloading from the server at 0:8080 without an SSL connection.
# gcc client.c -o client -lssl -lcrypto && ./client 0 8080 false download client.mp4 ./downloads/client.mp4


