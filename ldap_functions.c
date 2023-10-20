#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "ldap_functions.h" // Include the header file

//declaring fctions, so i can use them before they are defined.
void sendBindResponse(int client_socket);


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

    // Construct and send the BindResponse
    sendBindResponse(client_socket);
    sleep(10);
    printf("End of the packet\n \n ");

    close(client_socket);
}

// Function to construct and send the BindResponse
void sendBindResponse(int client_socket) {
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
}
