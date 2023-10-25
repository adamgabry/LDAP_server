#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

    #define DEBUG 1
    #define PORT 389

    void sendBindResponse(int client_socket);
    void handleBindRequest(int client_socket);

#endif
