#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define DEBUG 1;
#define PORT 3890

// Function to handle BindRequest
void handleBindRequest(int client_socket) {
    char bind_request[1024];
    int bind_request_length;

    // Receive the BindRequest from the client
    bind_request_length = recv(client_socket, bind_request, sizeof(bind_request), 0);
    if (bind_request_length <= 0) {
        perror("Error receiving BindRequest");
        close(client_socket);
        return;
    }

    // Print the BindRequest in hex format
    #ifdef DEBUG
        printf("Received BindRequest from client:\n");
        for (int i = 0; i < bind_request_length; i++) {
            printf("%02x ", (unsigned char)bind_request[i]);
        }
        printf("\n");
    #endif
    
    // Parse the BindRequest
    //int version = bind_request[0];
    int dn_length = bind_request[1];
    char dn[1024];
    memcpy(dn, &bind_request[2], dn_length);
    dn[dn_length] = '\0';
    int credentials_length = bind_request[2 + dn_length + 1];
    char credentials[1024];
    memcpy(credentials, &bind_request[2 + dn_length + 2], credentials_length);
    credentials[credentials_length] = '\0';

    // Construct the BindResponse
    char bind_response[1024];
    const unsigned char bind_data[] = {0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    int bind_data_length = sizeof(bind_data);

    // Make sure bind_response has enough space for bind_data
    memcpy(bind_response, bind_data, bind_data_length);

// The actual length is the same as bind_data_length
int bind_response_length = bind_data_length;
    printf("BindResponse lenght: %d \n Sent BindResponse to the client:", bind_response_length);
    for (int i = 0; i < bind_response_length; i++) {
        printf("%02x ", (unsigned char)bind_response[i]);
    }
    printf("\n");
    // Send the BindResponse to the client
    send(client_socket, bind_response, bind_response_length, 0);


    close(client_socket);
}

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
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen only on localhost
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