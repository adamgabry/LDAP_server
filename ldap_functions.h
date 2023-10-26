#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

    #define PORT 389
    #define DEBUG 1

    //macro for DEBUG printing
    #ifdef DEBUG
        #define DEBUG_PRINT(message) std::cout << message << std::endl
        #else
        #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
    #endif

    void sendBindResponse(int client_socket);
    void handleBindRequest(int client_socket);

#endif
