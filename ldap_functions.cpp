#include <iostream>
#include <cstring>
#include <unistd.h>
#include <iomanip> 
#include <sys/socket.h>
#include "ldap_functions.h"

void handleBindRequest(int client_socket);
void sendBindResponse(int client_socket);
void addTestEntry();

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
        std::cout << "Received BindRequest from client:" << std::endl;
        for (int i = 0; i < bind_request_length; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bind_request[i] << " ";
        }
        std::cout << std::endl;
    #endif

    // Parse the BindRequest
    // int version = bind_request[0];
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
    std::cout << "End of the packet\n \n ";
    close(client_socket);
}

void sendBindResponse(int client_socket) {
    // Construct the BindResponse
    char bind_response[1024];
    const unsigned char bind_data[] = {0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    int bind_data_length = sizeof(bind_data);

    // Make sure bind_response has enough space for bind_data
    memcpy(bind_response, bind_data, bind_data_length);

        if(DEBUG) std::cout << std::dec; //print in decimal
        DEBUG_PRINT("BindResponse length: " << bind_data_length << "\nSent BindResponse to the client:");

    for (int i = 0; i < bind_data_length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bind_response[i] << " ";
    }
    std::cout << std::endl;

    // Send the BindResponse to the client
    send(client_socket, bind_response, bind_data_length, 0);
}

void addTestEntry()
{
    // Define the LDIF-style entry as a string
    const char* testEntryLDIF = "dn: uid=xgabry01,dc=vutbr,dc=cz\n"
                                "objectClass: top\n"
                                "objectClass: person\n"
                                "objectClass: organizationalPerson\n"
                                "objectClass: inetOrgPerson\n"
                                "uid: xgabry01\n"
                                "cn: xgabry01\n"
                                "mail: xgabry01@vutbr.cz\n";
    // You would need to implement the code to parse and process the LDIF entry.
    // In a real LDAP server, this would involve adding the entry to your data store.

    // For this simplified example, let's just print the LDIF content.
    std::cout << "Adding test entry:" << std::endl << testEntryLDIF << std::endl;
}