#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

#include <iostream>
#include <cstring>
#include <string.h>
#include <vector>
#include <set>
#include <unistd.h>
#include <iomanip> 
#include <sys/socket.h>
#include "ldap_functions.h"

#define PORT 389
#define DEBUG 1

using namespace std;

//macro for DEBUG printing
#ifdef DEBUG
    #define DEBUG_PRINT(message) std::cout << message << std::endl
    #else
    #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
#endif

class message
    {
    public:
        int protocol_type;
        int id;
        int lenght;
        int message_type;
        int version;
    };

class ldap_functions{
private:

    int byte_index;     //act
    /*
    *header for checking message in check_ldap_FSM_state
    */
    int client_message_header; //fd
    int client_message_body;
    int byte_content; //ch

    set<vector<string>> database;
    message mess;


    void next_byte(int client_message, size_t amount);
public:
    /*constructor*/
    ldap_functions(int client_socket, set<vector<string>> database);

    bool check_ldap_FSM_state();

    bool choose_ldap_message();

    bool handleBindRequest();

    void sendBindResponse();

    int get_mess_length();

    int reset_content(int var);
};
#endif
