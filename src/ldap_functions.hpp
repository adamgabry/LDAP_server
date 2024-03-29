/**
 * @file ldap_functions.hpp
 * @author Adam Gabrys
 * @login xgabry01
 */


#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

#include <iostream>
#include <memory>
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
#include <regex>

#define LDAP_PACKET 0x30
#define LDAP_PACKET_STRING "\x30"
#define SIMPLE_BIND 0x01

//ASN TAGS
#define ASN_TAG_EOC 0x00
#define ASN_TAG_BOOL 0x01
#define ASN_TAG_INTEGER 0x02
#define ASN_TAG_BIT_STRING 0x03
#define ASN_TAG_OCTETSTRING 0x04
#define BER_TAG_SEQUENCE 0x30
#define ASN_TAG_ENUMERATED 0x0A

//LDAP MESSAGE TYPES
#define BINDREQUEST 0x60
#define BINDRESPONSE 0x61
#define SEARCHREQUEST 0x63
#define SEARCHRESENTRY 0x64
#define SEARCHRESENTRY_STRING "\x64"
#define SEARCHRESDONE 0x65
#define UNBINDREQUEST 0x42


/// Set to 1000 based on this source:
/// @source https://forums.ivanti.com/s/article/LDAP-Error-Search-Size-Limit-Exceeded?language=en_US
/// @date 10.11.2023
/// @brief The maximum number of entries that can be returned from a search request.
#define SIZE_LIMIT 1000

//FILTERS
#define AND 0xA0
#define OR 0xA1
#define NOT 0xA2
#define EQUALITY_MATCH 0xA3
#define SUBSTRING 0xA4

#define FILTER_INITIAL 0x80
#define FILTER_ANY 0x81
#define FILTER_FINAL 0x82

#define FILTER_ANY_SIGN ".*"
using namespace std;

//#define DEBUG 1

//macro for DEBUG printing
#ifdef DEBUG
    #define DEBUG_PRINT(message) std::cout << message << std::endl
    #define DEBUG_PRINT_BYTE_CONTENT DEBUG_PRINT("byte content: " << hex << byte_content);
    #else
    #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
    #define DEBUG_PRINT_BYTE_CONTENT DEBUG_PRINT();
#endif

class ldap_filters {
public:
    int filter_type; //= -1; // securing that filter_type is not empty and not equal to any filter type
    
    int attr_desc_length; //length of the attribute description
    string attr_desc;   //attribute descriptor value

    int attr_value_length; //length of the attribute value
    string attr_value; //attribute value

    int filter_length; 
    vector<ldap_filters> filters; 
};

/**
 * @brief Represents an LDAP message.
 */
class message
{
    public:
        int protocol_type;
        int id;
        int lenght;
        int message_type;
        int size_limit;
        bool size_limit_exceeded = false;
};

/**
 * @brief Class representing LDAP functions.
 * 
 */
class ldap_functions
{
private:
    /**
     * @brief Reads the next byte from the client message.
     * 
     * @param client_message the client message to read from.
     * @param amount the amount of bytes to read.
     */
    void next_byte(int client_message, size_t amount);
    ldap_filters filter;
    
public:
    int byte_index;             //actual byte index
    int client_message_header;  //header for checking message in check_ldap_FSM_state
    int client_message_body;
    int byte_content;           //content of the byte
    string dn;                  //dn content for search request
    set<vector<string>> database;
    message mess;
    set<vector<string>> filters_applied; //all filters applied to the database
    string filter_attribute_desc;       //attribute description of the filter


    /*constructor*/
    /**
     * @brief Construct a new ldap_functions object.
     * 
     * @param client_socket the client socket to use.
     * @param database the database to use.
     */
    ldap_functions(int client_socket, set<vector<string>> database);

    /**
     * @brief Checks the current state of the LDAP finite state machine.
     * 
     * @return true if the current state is valid, false otherwise.
     */
    bool check_ldap_FSM_state();

    /**
     * @brief Chooses the LDAP message to handle.
     * 
     * @return true if the message was handled successfully, false otherwise.
     */
    bool choose_ldap_message();

    /**
     * @brief Handles the BindRequest message.
     * 
     * @return true if the message was handled successfully, false otherwise.
     */
    bool handleBindRequest();

    /**
     * @brief Sends the BindResponse message.
     * 
     */
    void sendBindResponse();

    /**
     * @brief Searches for an entry in the database.
     * 
     */
    void search_entry();

    /**
     * @brief Sends the succesfull SearchResDone message.
     * 
     */
    void search_res_done();

    /**
     * @brief Prints the constructed response for debugging purposes.
     * 
     * @param bind_data_length the length of the bind data.
     * @param bind_response the bind response to print.
     */
    void debug_print_constructed_response(int bind_data_length, char* bind_response);

    /**
     * @brief Handles the SearchRequest message.
     * 
     * @return true if the message was handled successfully, false otherwise.
     */
    bool handleSearchRequest();

    /// @brief Reads the DN content from the client message.
    /// @brief Already makes ready the byte index to the next byte after the DN content
    /// @param dn_length based on the length of the DN
    void get_base_content(int lenght);

    /**
     * @brief Gets the length of the message.
     * @attention when returning from this function, sets already next byte to the buffer!
     * 
     * @return int the length of the message.
     */
    int get_mess_length();

    /**
     * @brief Checks if the next byte content equals to the given hex value.
     * 
     * @param hex_value the hex value to check.
     * @return int the next byte content.
     */
    int next_byte_content_equals_to(int hex_value);

    /**
     * @brief Checks if this byte content equals to the given hex value.
     * 
     * @param hex_value the hex value to check.
     * @return int the byte content.
     */
    int this_byte_content_equals_to(int hex_value);

    /**
     * @brief Checks if the next byte content is bigger than the given hex value.
     * 
     * @param hex_value the hex value to check.
     * @return int the next byte content.
     */
    int next_byte_content_bigger_than(int hex_value);

    /**
     * @brief Gets the filter.
     * 
     * @return ldap_filters the filter.
     */
    ldap_filters get_filter();

    /**
     * @brief Performs a search with the given filter.
     * 
     * @param f the filter to use.
     * @return set<vector<string>> the results of the search.
     */
    set<vector<string>> performSearch(ldap_filters f);

    /**
     * @brief Gets the LV string.
     * 
     * @param s the string to use.
     * @return string the LV string.
     */
    string LV_string(string s);

    /**
     * @brief Gets the LV id.
     * 
     * @param num the id to use.
     * @return string the LV id.
     */
    string LV_id(int num);
    
    /**
     * @brief Gets the limit.
     * 
     * @return int the limit.
     */
    int get_limit();

    /**
     * @brief Gets the string.
     * 
     * @param length the length to use.
     * @return string
     */
    string get_string(int length);

    /**
     * @brief sends the size limit exceeded message to the client using searchResDone.
     */
    void sendSizeLimitExceededMessage();
};
#endif
