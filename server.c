
//standart libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

//custom libraries
#include "ldap_functions.h"


int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(1);
    }

    // Configure the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all intefraces
    server_addr.sin_port = htons(PORT); // LDAP default port


    // Bind the socket to the server address
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(server_socket);
        exit(1);
    }

    // Start listening for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Error listening");
        close(server_socket);
        exit(1);
    }

    printf("LDAP server is listening on port %d...\n", PORT);

    while (1) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }
        printf("Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        // Handle the BindRequest for the client
        handleBindRequest(client_socket);
        printf("End of the packet\n \n ");
    }

    close(server_socket);
    return 0;
}