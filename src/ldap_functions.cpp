/**
 * @file ldap_functions.cpp
 * @author Adam Gabrys
 * @login xgabry01
 */


#include "ldap_functions.hpp"

ldap_functions::ldap_functions(int client_socket, set<vector<string>> data)
{
    database = data;
    client_message_header = client_socket;  //just for checking header
    client_message_body = client_socket;    //checking body of message
    byte_content = 0;
}


/// BREAKDOWN OF LDAP MESSAGE HEADER
/*   30 0c 02 01 01 60 07 02 01 03 04 00 80 00
*
byte|    
1   |30 - LDAP packet header -indicates LDAP message type
2   |   0c - length of the message
3   |      02 - messageID  
4   |         01 - BindReqmess
5   |            01 - simple bind
6>  |               60 - type of ldap message (bindreq, searchreq, unbindreq)
*/ 
bool ldap_functions::check_ldap_FSM_state()
{
    read(client_message_header,&byte_content, 1); //read one byte

    DEBUG_PRINT("LDAP packet type "<< hex << byte_content);
    if(byte_content != LDAP_PACKET) return 0; //ignore(so return false)
    
    next_byte(client_message_header, 1);

    mess.lenght = get_mess_length();

    DEBUG_PRINT("LDAP packet length "<< dec << mess.lenght);

    DEBUG_PRINT("LDAP type "<< hex << byte_content); //here 0x2 is INTEGER, must be there
    if(byte_content != ASN_TAG_INTEGER) return 0; //ignore(so return false)
    
    next_byte(client_message_header, 1);    //  L
    next_byte(client_message_header, 1);    //  V 4th byte message ID
    mess.id = byte_content;                 //  get message id fction?

    DEBUG_PRINT("mess id "<< hex << byte_content);  

    next_byte(client_message_header, 1);

    mess.message_type = byte_content; //saving type of LDAP_message
    DEBUG_PRINT("LDAP mess type "<< hex << mess.message_type);

    if(choose_ldap_message()) return 1; //when everything ok, it has to return true
        return 0;
}

/*
In this function we are assuring, that it doesnt matter in what order came BindRequest or SearchRequest
*/
bool ldap_functions::choose_ldap_message()
{
    switch(mess.message_type)
    {
        case BINDREQUEST:
            return handleBindRequest();
            break;
        case SEARCHREQUEST:
            return handleSearchRequest();
            break;
        case UNBINDREQUEST:
            DEBUG_PRINT_BYTE_CONTENT;
            DEBUG_PRINT("\n UNBINDREQUEST \n");
            return 0;
            break;
        default:
            return 0;
    }
} 

bool ldap_functions::handleBindRequest() // zkracuje jelikoz pracuju s clientmessage a read
{
    DEBUG_PRINT("\n----BIND REQ----\n");

    next_byte(client_message_header, 1);

    int bindreq_length = get_mess_length();

    DEBUG_PRINT("Bindreq length is: "<< hex << bindreq_length);

    next_byte(client_message_header, 2);

    DEBUG_PRINT("Version and authentification type: "<< hex << byte_content);
    
    if(!(byte_content == 0x201 || byte_content == 0x301)) return 0; //ldap v(2|3) and simple bind(1)
    
    byte_content = 0;// reseting

    next_byte(client_message_header, 1); // Move to the next byte (DN length)

    DEBUG_PRINT("DN length: " << hex << byte_content);

    string dn = "";
    for (int i = 0; i < get_mess_length(); i++, next_byte(client_message_header, 1)) {
        dn += byte_content;
        DEBUG_PRINT(" byte content: " << byte_content);
    }
    
    DEBUG_PRINT("Distinguished Name: " << dn);
    DEBUG_PRINT("\n-----END OF BIND REQ-----");

    sendBindResponse();
    //sleep(5); //uncomment for testing purpose of nonblocking sockets
    DEBUG_PRINT("\nEnd of the packet");

    return 1;
}

void ldap_functions::sendBindResponse() 
{    
    DEBUG_PRINT("\n-----START OF BIND RES----- \n");

    char bind_response[1024];
    const unsigned char bind_data[] = {0x30,  static_cast<unsigned char>(mess.lenght),
                                      static_cast<unsigned char>(ASN_TAG_INTEGER), 0x01,
                                      static_cast<unsigned char>(mess.id),
                                      BINDRESPONSE, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    int bind_data_length = sizeof(bind_data);

    //copy bind_data to bind_response
    memcpy(bind_response, bind_data, bind_data_length );

    debug_print_constructed_response(bind_data_length, bind_response);
    
    // Send the BindResponse to the client
    send(client_message_header, bind_response, bind_data_length, 0);

    DEBUG_PRINT("\n-----END OF BIND RES-----");
}
