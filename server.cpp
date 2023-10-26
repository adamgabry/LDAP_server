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
#include "server.h"

#define ERR 1

void* client_handler(void* arg) {
    int client_socket = *((int*)arg);
    free(arg); // Free the allocated memory

    handleBindRequest(client_socket);

    return NULL;
}

server::server(int port) {

    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Configure the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(port); 

    // Bind the socket to the server address
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Error listening");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
}
void server::connect_clients(){
    while (1) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }
        int client_num = 1;

        std::cout << "Client " << client_num << ": Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
        client_num++;

        // Create a new thread to handle the client
        client_socket_ptr = (int*)malloc(sizeof(int));
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
}

int main() {

    server ser(PORT);

    std::cout << "LDAP server is listening on port " << PORT << "..." << std::endl;
    
    ser.connect_clients();

    return 0;
}
