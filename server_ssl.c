#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define TRUE 1
#define FALSE 0
#define PORT 8080
#define MAX 30

// Structure to hold information about client connections
struct node {
    int controller_fd;      // File descriptor for the controller connection
    int remote_fd;          // File descriptor for the remote connection
    char id[32];            // Identifier for the client
    SSL *controller_ssl;    // SSL object for the controller connection
    SSL *remote_ssl;        // SSL object for the remote connection
};

// Function to search for a client by identifier
int search(struct node list[], char res[]) {
    for (int i = 0; i < MAX; i++) {
        if (strncmp(list[i].id, res, 32) == 0) {
            return i;
        }
    }
    return -1;
}

// Function to search for a client by file descriptor
int search_fd(struct node list[], int fd) {
    for (int i = 0; i < MAX; i++) {
        if ((fd == list[i].remote_fd) || (fd == list[i].controller_fd)) {
            return i;
        }
    }
    return -1;
}

// Function to search for a free slot in the list of clients
int search_free(struct node list[]) {
    for (int i = 0; i < MAX; i++) {
        if (list[i].id[0] == '\0') {
            return i;
        }
    }
    return -1;
}

int main(int argc, char *argv[]) {
    int opt = TRUE;
    int master_socket, addrlen, new_socket, activity, i, valread;
    int max_sd, sd;
    SSL *selected_ssl;
    struct sockaddr_in address;
    struct node list[MAX];
    int j, index = 0, v;
    char buffer[1025]; // Data buffer of 1K

    // Set of socket descriptors
    fd_set readfds;

    // Initialize the list of client connections
    for (i = 0; i < MAX; i++) {
        list[i].remote_fd = 0;
        list[i].controller_fd = 0;
        list[i].id[0] = '\0';
        list[i].remote_ssl = 0;
        list[i].controller_ssl = 0;
    }

    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();

    // Create SSL context using SSLv23 server method
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        printf("could not SSL_CTX_new\n");
        return 1;
    }

    // Load certificate
    const char *certificate = "./certificate.pem";
    if (SSL_CTX_use_certificate_file(ssl_ctx, certificate, SSL_FILETYPE_PEM) != 1) {
        printf("could not SSL_CTX_use_certificate_file\n");
        return 1;
    }

    // Load private key
    const char *privateKey = "./key.pem";
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, privateKey, SSL_FILETYPE_PEM) != 1) {
        printf("could not SSL_CTX_use_PrivateKey_file\n");
        return 1;
    }

    // Create a master socket
    master_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (master_socket == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set master socket to allow multiple connections
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to localhost port 8080
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Listener on port %d \n", PORT);

    // Try to specify maximum of 3 pending connections for the master socket
    if (listen(master_socket, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept the incoming connections
    addrlen = sizeof(address);
    puts("Waiting for connections ...");

    while (TRUE) {
        // Clear the socket set
        FD_ZERO(&readfds);

        // Add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        // Add child sockets to set
        for (i = 0; i < MAX; i++) {
            sd = list[i].remote_fd;
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            if (sd > max_sd) {
                max_sd = sd;
            }
            sd = list[i].controller_fd;
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            if (sd > max_sd) {
                max_sd = sd;
            }
            // Highest file descriptor number, needed for the select function
        }

        // Wait for activity on one of the sockets, timeout is NULL so wait indefinitely
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        }

        // If something happened on the master socket, it's an incoming connection
        if (FD_ISSET(master_socket, &readfds)) {

            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept error");
            }

            SSL *ssl = SSL_new(ssl_ctx);
            if (!ssl) {
                printf("could not SSL_new\n");
                return 1;
            }
            if (!SSL_set_fd(ssl, new_socket)) {
                close(new_socket);
                printf("could not SSL_set_fd\n");
                return 1;
            }
            SSL_set_accept_state(ssl);

            do {
                valread = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                buffer[valread] = '\0';
                if (strncmp(buffer, "remote", 6) == 0) {
                    char *res = strchr(buffer, ':');
                    if (res == NULL) {
                        perror("id not given");
                        close(new_socket);
                        SSL_free(ssl);
                        break;
                    } else if (search(list, res + 1) >= 0) {
                        perror("remote id already exists");
                        close(new_socket);
                        SSL_free(ssl);
                        break;
                    } else {
                        index = search_free(list);
                        strncpy(list[index].id, res + 1, 32);
                        list[index].remote_fd = new_socket;
                        list[index].remote_ssl = ssl;
                        printf("remote client added\n");
                    }
                } else if (strncmp(buffer, "controller", 10) == 0) {
                    char *res = strchr(buffer, ':');
                    if (res == NULL) {
                        perror("id not given");
                        close(new_socket);
                        SSL_free(ssl);
                        break;
                    }
                    i = search(list, res + 1);
                    if (i < 0) {
                        perror("remote id not found");
                        close(new_socket);
                        SSL_free(ssl);
                        break;
                    }
                    list[i].controller_fd = new_socket;
                    list[i].controller_ssl = ssl;
                    printf("controller client added\n");
                } else {
                    printf("%s\n", buffer);
                    perror("wrong tag");
                    close(new_socket);
                    SSL_free(ssl);
                    break;
                }
                // Inform user of socket number - used in send and receive commands
                printf("New SSL connection, socket fd is %d , ip is : %s , port : %d \n",
                       new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            } while (0);
        }

        // Else it's some IO operation on some other socket
        for (i = 0; i < MAX; i++) {
            int k;
            for (k = 0; k < 2; k++) {
                if (k == 0) {
                    sd = list[i].remote_fd;
                    selected_ssl = list[i].remote_ssl;
                    if (sd == 0) {
                        continue;
                    }
                } else {
                    sd = list[i].controller_fd;
                    selected_ssl = list[i].controller_ssl;
                    if (sd == 0) {
                        continue;
                    }
                }

                if (FD_ISSET(sd, &readfds)) {
                    valread = SSL_read(selected_ssl, buffer, sizeof(buffer) - 1);
                    buffer[valread] = '\0';
                    if (valread == 0) {
                        // Somebody disconnected, get their details and print
                        j = search_fd(list, sd);
                        getpeername(list[j].remote_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                        printf("Remote disconnected %d, ip %s , port %d \n",
                               list[j].remote_fd, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                        close(list[j].remote_fd);
                        SSL_free(list[j].remote_ssl);

                        getpeername(list[j].controller_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                        printf("Controller disconnected %d, ip %s , port %d \n",
                               list[j].controller_fd, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                        close(list[j].controller_fd);
                        SSL_free(list[j].controller_ssl);

                        list[j].remote_fd = 0;
                        list[j].controller_fd = 0;
                        list[j].id[0] = '\0';
                        list[j].remote_ssl = 0;
                        list[j].controller_ssl = 0;
                    } else {
                        // Echo back the message that came in
                        j = search_fd(list, sd);
                        if (list[j].controller_fd != 0) {
                            if (list[j].remote_fd == sd) {
                                v = SSL_write(list[j].controller_ssl, buffer, strlen(buffer));
                            } else if (list[j].controller_fd == sd) {
                                v = SSL_write(list[j].remote_ssl, buffer, strlen(buffer));
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

