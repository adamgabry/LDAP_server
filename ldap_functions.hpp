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

#define PORT 389
#define DEBUG 1
#define LDAP_PACKET 0x30
#define LDAP_PACKET_LENGTH 0x0c
#define SIMPLE_BIND 0x01
#define ASN_TAG_INTEGER 0x2

#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQUEST 0x63
#define SEARCHRESENTRY 0x64
#define SEARCHRESDONE 0x65
#define UNBINDREQUEST 0x42

using namespace std;

//macro for DEBUG printing
#ifdef DEBUG
    #define DEBUG_PRINT(message) std::cout << message << std::endl
    #else
    #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
#endif

//macro for debug printing byte content
#define DEBUG_PRINT_BYTE_CONTENT DEBUG_PRINT("byte content: " << hex << byte_content);

class message
    {
    public:
        int protocol_type;
        int id;
        int lenght;
        int message_type;
        int size_limit;
        int time_limit;
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
    string dn;      //dn content for search request

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

    bool handleSearchRequest();

    /// @brief Reads the DN content from the client message.
    /// @brief Already makes ready the byte index to the next byte after the DN content
    /// @param dn_length based on the length of the DN
    void getDNcontent(int lenght);

    int get_mess_length();

    int next_byte_content_equals_to(int hex_value);

    int next_byte_content_bigger_than(int hex_value);
};
#endif
