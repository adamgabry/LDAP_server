#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080

typedef struct {
    int messageID;
    int version;
    char bindDN[256];
    char password[256];
} BindRequest;

typedef struct {
    int messageID;
    int resultCode;
    char errorMessage[256];
} BindResponse;

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    BindRequest bindRequest;
    BindResponse bindResponse;

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Accept incoming connections and handle BindRequest
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        // Read BindRequest message from client
        read(new_socket, &bindRequest, sizeof(BindRequest));

        // Verify username and password
        if (strcmp(bindRequest.bindDN, "cn=admin,dc=example,dc=com") == 0 &&
            strcmp(bindRequest.password, "password") == 0) {
            // Send BindResponse indicating success
            bindResponse.messageID = bindRequest.messageID;
            bindResponse.resultCode = 0;
            strcpy(bindResponse.errorMessage, "");
            write(new_socket, &bindResponse, sizeof(BindResponse));
        } else {
            // Send BindResponse indicating failure
            bindResponse.messageID = bindRequest.messageID;
            bindResponse.resultCode = 49;
            strcpy(bindResponse.errorMessage, "Invalid credentials");
            write(new_socket, &bindResponse, sizeof(BindResponse));
        }

        close(new_socket);
    }

    return 0;
}
