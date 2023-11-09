#include "ldap_functions.h"

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

ldap_functions::ldap_functions(int client_socket, set<vector<string>> data)
{
    database = data;
    client_message_header = client_socket;  //just for checking header
    client_message_body = client_socket;    //checking body of message
    byte_index = 0;
    byte_content = 0;
}
void ldap_functions::next_byte(int client_message,size_t amount){
    read(client_message,&byte_content, amount); //read one byte
    byte_index += amount;
    //DEBUG_PRINT("bytes read: " << dec << byte_index);
}


//MAY NOT BE CORRECT FOR LONGER THAN 0x80
int ldap_functions::get_mess_length() {
    int length = byte_content & 0x7F;  // Initialize with the low 7 bits of the first byte
    next_byte(client_message_header, 1);  // Move to the next byte

    if (length < 0x81) {
        return length;
    }
    int shift = 7;  // Number of bits to shift left
    while (byte_content & 0x80) {
        length |= ((byte_content & 0x7F) << shift);
        shift += 7;
        next_byte(client_message_header, 1);  // Move to the next byte
    }

    // Add the final byte (low 7 bits) to the length
    length |= (byte_content << shift);

    return length;
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
    
    next_byte(client_message_header, 1);    //  3rd byte message ID
    mess.id = byte_content;                 //  get message id fction?
    DEBUG_PRINT("mess id "<< hex << byte_content); 

    next_byte(client_message_header, 1);

    next_byte(client_message_header, 1);

    mess.message_type = byte_content; //saving type of LDAP_message
    DEBUG_PRINT("LDAP mess type "<< hex << mess.message_type);

    if(choose_ldap_message()) return 1; //when everything ok, it has to return true
        return 0;
}

bool ldap_functions::choose_ldap_message()
{
    switch(mess.message_type)
    {
        case BINDREQUEST:
            return handleBindRequest();
            break;
        case SEARCHREQUEST:
            DEBUG_PRINT("SEARCHREQUEST");
            return 0;
            break;
        case UNBINDREQUEST:
            return 0;
            break;
        default:
            return 0;
    }
} 

bool ldap_functions::handleBindRequest() // zkracuje jelikoz pracuju s clientmessage a read
{

    DEBUG_PRINT("----BIND----");
    next_byte(client_message_header, 1);
    DEBUG_PRINT("Bindreq length is: "<< hex << get_mess_length());

    next_byte(client_message_header, 2);
    DEBUG_PRINT("Version and authentification type: "<< hex << byte_content);
    
    if(!(byte_content == 0x201 || byte_content == 0x301)) return 0; //ldap v(2|3) and simple bind(1)
    
    byte_content = 0;

    next_byte(client_message_header, 1); // Move to the next byte (DN length)
    DEBUG_PRINT("DN length: " << hex << byte_content);

    // Read the DN based on the DN length


    string dn = "";
    for (int i = 0; i < get_mess_length(); i++, next_byte(client_message_header, 1)) {
        dn += byte_content;
        DEBUG_PRINT(" byte content: " << byte_content);
    }
    
    DEBUG_PRINT("Distinguished Name: " << dn);
    byte_index = 0;
    DEBUG_PRINT("-----END OF BIND-----");

    sendBindResponse();
    //sleep(5);
    DEBUG_PRINT("End of the packet");

    return true;
}

void ldap_functions::sendBindResponse() {
    // Construct the BindResponse
    char bind_response[1024];
    //                                        int to unsigned char
    const unsigned char bind_data[] = {0x30,  static_cast<unsigned char>(mess.lenght),  static_cast<unsigned char>(ASN_TAG_INTEGER), 0x01, static_cast<unsigned char>(mess.id), BINDRESPONSE, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    int bind_data_length = sizeof(bind_data);

    // Make sure bind_response has enough space for bind_data
    memcpy(bind_response, bind_data, bind_data_length);

    if(DEBUG)
    {
        DEBUG_PRINT("BindResponse length: "<< dec << bind_data_length << "\nSent BindResponse to the client:");
        for (int i = 0; i < bind_data_length; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bind_response[i] << " ";
        }
        std::cout << std::endl;
    }
    // Send the BindResponse to the client
    send(client_message_header, bind_response, bind_data_length, 0);
}


//bindresponse
    /*
    char bind_request[1024];
    int bind_request_length;

    // Receive the BindRequest from the client
    bind_request_length = recv(client_message_header, bind_request, sizeof(bind_request), 0);
    if (bind_request_length <= 0) 
    {
        perror("Error receiving BindRequest");
        close(client_message_header);
        return;
    }

    // Print the BindRequest in hex format
    #ifdef DEBUG
        cout << "Received BindRequest from client:" << endl;
        for (int i = 0; i < bind_request_length; i++) {
            cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)bind_request[i] << " ";
        }
        cout << endl;
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
*/