#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <netinet/in.h>

#define PORT 8080

int main(int argc, char *argv[]) {
    int status, valread, client_fd;
    int iRet;
    struct sockaddr_in serv_addr;
    char bufferIn[1024] = { 0 };
    char bufferOut[1024] = { 0 };

    // Check for correct number of command line arguments
    if (argc < 3){
        fprintf (stderr, "Invalid arguments\nusage: SockClient <ip addr> <identifier>\n");
        exit(1);
    }

    // Initialize SSL library
    SSL_library_init();
    SSL_load_error_strings();
   
    // Create SSL context
    SSL_CTX* ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx) {
        printf("could not SSL_CTX_new\n");
        return 1;
    }

    // Create a socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        fprintf(stderr, "\n Socket creation error \n");
        return -1;
    }

    // Create a new SSL structure for SSL connection
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("could not SSL_new\n");
        return 1;
    }

    // Set server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address from text to binary form
    iRet = inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);
    if (iRet <= 0) {
        fprintf(stderr, "\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to the server
    status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (status < 0) {
        fprintf(stderr, "\nConnection Failed \n");
        return -1;
    }

    // Set the file descriptor for SSL connection
    if (!SSL_set_fd(ssl, client_fd)) {
        close(client_fd);
        printf("could not SSL_set_fd\n");
        return 1;
    }

    // Set SSL connection state to connect
    SSL_set_connect_state(ssl);

    // Initiate SSL handshake
    int action = SSL_connect(ssl);
    if(action < 0){
        fprintf(stderr, "\nSSL Connection Failed \n");
        return -1;
    }

    // Send identifier to the server
    sprintf (bufferIn, "controller:%s\n", argv[2]);
    SSL_write(ssl, bufferIn, strlen(bufferIn));
    
    // Fork a new process
    int pid1 = fork();

    if (pid1 == 0){
        // Child process
        while(1){
            // Read input from user
            valread = read(0, bufferIn, sizeof(bufferIn) - 1);
            bufferIn[valread] = '\0';
            // Send input to the server
            SSL_write(ssl, bufferIn, strlen(bufferIn));
        }
    }else{
        // Parent process
        while(1){
            // Read data from server
            valread = SSL_read(ssl, bufferOut, sizeof(bufferOut) - 1);
            if (valread > 0){
                bufferOut[valread] = '\0';
                // Print received data
                printf("%s",bufferOut);
            }                    
            if (valread == 0){
                break;
            }
        }
    }
   
    // Close the connected socket
    close(client_fd);
    // Free the SSL structure
    SSL_free(ssl);
    return 0;
}

