/**
 * @file handle_search_res_done.cpp
 * @author Adam Gabrys
 * @login xgabry01
 */

#include "ldap_functions.hpp"


/**
 * @brief Handles the completion of a search result operation.
 * 
 * This function constructs a response message and sends it to the client.
 * The response message contains the search result completion status and data.
 */
void ldap_functions::search_res_done()
{
    DEBUG_PRINT("\n-----START OF SEARCH RES DONE-----\n");
    
    string res = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    res = LDAP_PACKET_STRING + LV_string("\x02" + LV_id(mess.id) + "\x65" + LV_string(res));
    
    DEBUG_PRINT("res: " << res);

    ///@arg 0 client_message_header is the socket to send the message to
    ///@arg 1 res is the message to send
    ///@arg 2 res length
    send(client_message_header, res.c_str(), res.length(), 0);

    DEBUG_PRINT("\n-----END OF SEARCH RES DONE-----\n");
}

/**
 * @brief Sends a size limit exceeded message to the client.
 * 
 * This function constructs an LDAP SearchResultDone message with the size limit exceeded result code
 * and sends it to the client.
 */
void ldap_functions::sendSizeLimitExceededMessage() 
{    
    DEBUG_PRINT("\n-----START OF SIZE LIMIT EXCEEDED RES----- \n");
    // Construct HARDCODED LDAP SearchResultDone message with size limit exceeded
    string resultCode = {0x0A, 0x01, 0x04}; // sizeLimitExceeded
    string searchResultDone = {LDAP_PACKET, 0x0D, 0x02, 0x01, static_cast<char>(mess.id), SEARCHRESDONE, 0x07, 0x0A, 0x01, 0x04, 0x04, 0x00};

    string ldapMessage = searchResultDone + resultCode;

    // Send the LDAP message
    send(client_message_header, ldapMessage.c_str(), ldapMessage.length(), 0);

    DEBUG_PRINT("\n-----END OF SIZE LIMIT EXCEEDED RES-----");
}