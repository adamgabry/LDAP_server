#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

#include <iostream>
#include <cstring>
#include <string.h>
#include <vector>
#include <set>
#include <unistd.h>
#include <iomanip> 
#include <map>
#include <sys/socket.h>
#include <limits>
#include <math.h>

#define PORT 389
#define LDAP_PACKET 0x30
#define SIMPLE_BIND 0x01

#define ASN_TAG_BOOL 0x01
#define ASN_TAG_INTEGER 0x02
#define ASN_TAG_BIT_STRING 0x03
#define ASN_TAG_OCTETSTRING 0x04

#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQUEST 0x63
#define SEARCHRESENTRY 0x64
#define SEARCHRESDONE 0x65
#define UNBINDREQUEST 0x42

#define SIZE_LIMIT 200

#define AND 0xA0
#define OR 0xA1
#define NOT 0xA2
#define EQUALITY_MATCH 0xA3
#define SUBSTRING 0xA4

using namespace std;

#define DEBUG 1

//macro for DEBUG printing
#ifdef DEBUG
    #define DEBUG_PRINT(message) std::cout << message << std::endl
    #define DEBUG_PRINT_BYTE_CONTENT DEBUG_PRINT("byte content: " << hex << byte_content);
    #else
    #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
    #define DEBUG_PRINT_BYTE_CONTENT DEBUG_PRINT();
#endif

//macro for debug printing byte content


class Filter {
public:
    int filter_type; //= -1; // securing that filter_type is not empty and not equal to any filter type
    
    int attr_desc_length;
    string attr_desc; 

    int attr_value_length;
    string attr_value; 

    int filter_length; 
    //TODO: redo this
    vector<Filter> filters; /**< Stored subfilters **/
    /**< Map for names of AttrDesc **/
    map<string, int> known = {{"cn", 0}, {"commonname", 0},
                              {"uid", 1}, {"userid", 1},
                              {"mail", 2}};
    int w; /**< Index of AttrDesc **/
};

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
    void next_byte(int client_message, size_t amount);
    Filter filter;
    
public:
    int byte_index;     //actual byte index
    int client_message_header; //header for checking message in check_ldap_FSM_state
    int client_message_body;
    int byte_content; //ch
    string dn;      //dn content for search request
    set<vector<string>> database;
    message mess;
    set<vector<string>> filters_applied; //all filters applied to the database

    /*constructor*/
    ldap_functions(int client_socket, set<vector<string>> database);

    bool check_ldap_FSM_state();

    bool choose_ldap_message();

    bool handleBindRequest();

    void sendBindResponse();

    void search_entry();

    void search_res_entry();

    void search_res_done();

    void debug_print_constructed_response(int bind_data_length, char* bind_response);

    bool handleSearchRequest();

    /// @brief Reads the DN content from the client message.
    /// @brief Already makes ready the byte index to the next byte after the DN content
    /// @param dn_length based on the length of the DN
    void getDNcontent(int lenght);

    int get_mess_length();

    int next_byte_content_equals_to(int hex_value);

    int this_byte_content_equals_to(int hex_value);

    int next_byte_content_bigger_than(int hex_value);

    Filter get_filter_content();

    Filter get_filter();

    set<vector<string>> performSearch(Filter f);

    string LV_string(string s);

    string LV_id(int num);
    
    int get_limit();

};
#endif
