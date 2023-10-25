// Standard C++ libraries
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

// Custom libraries
#include "ldap_functions.h"

#define ERR 1

void* client_handler(void* arg) {
    int client_socket = *((int*)arg);
    free(arg); // Free the allocated memory

    handleBindRequest(client_socket);

    close(client_socket);
    return NULL;
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(ERR);
    }

    // Configure the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(PORT); // LDAP default port

    // Bind the socket to the server address
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(server_socket);
        exit(ERR);
    }

    // Start listening for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Error listening");
        close(server_socket);
        exit(ERR);
    }

    std::cout << "LDAP server is listening on port " << PORT << "..." << std::endl;
    int i = 1;
    while (1) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }

        std::cout << "Client " << i << ": Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
        i++;

        // Create a new thread to handle the client
        int* client_socket_ptr = (int*)malloc(sizeof(int));
        *client_socket_ptr = client_socket;

        // Start handling the communication with the client
        // If unsuccessful, close the client socket and free the allocated memory
        // Here, client_handler is the function that calls the handleBindRequest function
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, client_socket_ptr) != 0) {
            perror("Error creating thread");
            close(client_socket);
            free(client_socket_ptr);
        }
    }

    close(server_socket);
    return 0;
}