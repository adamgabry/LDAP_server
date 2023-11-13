#include "ldap_functions.hpp"


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

    //the MSB in octet represents whether there are more octets to follow
    //if the 7th bit is set to 1, so we have to read more bytes
    while (byte_content & 0x80) {
        length |= ((byte_content & 0x7F) << shift);
        shift += 7;
        next_byte(client_message_header, 1);  // Move to the next byte
    }
    // Add the final byte (low 7 bits) to the length
    length |= (byte_content << shift);

    return length ;
}

void ldap_functions::getDNcontent(int dn_length) {
    dn = "";
    next_byte(client_message_header, 1); //move from the byte with dn length content
    for (int i = 0; i < dn_length - 1 ; i++) {
        dn += byte_content;
        next_byte(client_message_header, 1);
        DEBUG_PRINT("dn content: " << dn);
    }
}

int ldap_functions::next_byte_content_equals_to(int hex_value)
{
    next_byte(client_message_header, 1);
    DEBUG_PRINT_BYTE_CONTENT;
    if(byte_content != hex_value) return 0;
    return 1;
}

int ldap_functions::next_byte_content_bigger_than(int hex_value) 
{
    next_byte(client_message_header, 1);
    DEBUG_PRINT_BYTE_CONTENT;
    if(byte_content > hex_value) return 0;
    return 1;
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
    
    DEBUG_PRINT("LDAP packet type "<< hex << byte_content); 
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
            return handleSearchRequest();
            break;
        case UNBINDREQUEST:
            return 0;
            break;
        default:
            return 0;
    }
} 

int ldap_functions::get_limit()
{
    
    next_byte(client_message_header, 1); //L

    int num_of_bytes = byte_content; 
    if(num_of_bytes <= 0) return -1; //cant be negative or zero

    next_byte(client_message_header, 1); //V
    int limit_value = 0;
    /*
    shift = number of bits to shift
    condition = number of bytes shifted is not negative
    then we decrement shift by 8(simulation of moving to the next byte for condition) and move to the next byte
    */
    for (int shift = (num_of_bytes - 1) * 8; shift >= 0; shift -= 8, next_byte(client_message_header, 1)) {
        limit_value += byte_content << shift; //constructing larger integer from a sequence of bytes with bit shifting
    }
    DEBUG_PRINT("limit value: " << dec << limit_value);
    return limit_value;
}

bool ldap_functions::handleBindRequest() // zkracuje jelikoz pracuju s clientmessage a read
{

    DEBUG_PRINT("\n----BIND REQ----\n");

    next_byte(client_message_header, 1);

    DEBUG_PRINT("Bindreq length is: "<< hex << get_mess_length());

    next_byte(client_message_header, 2);

    DEBUG_PRINT("Version and authentification type: "<< hex << byte_content);
    
    if(!(byte_content == 0x201 || byte_content == 0x301)) return 0; //ldap v(2|3) and simple bind(1)
    
    byte_content = 0;// reseting

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
    DEBUG_PRINT("\n-----END OF BIND REQ-----");

    sendBindResponse();
    //sleep(5);
    DEBUG_PRINT("\nEnd of the packet");

    return true;
}
void ldap_functions::sendBindResponse() 
{    
    DEBUG_PRINT("\n-----START OF BIND RES----- \n");
    char bind_response[1024];
                                              //int to unsigned char
    const unsigned char bind_data[] = {0x30,  static_cast<unsigned char>(mess.lenght),  static_cast<unsigned char>(ASN_TAG_INTEGER), 0x01, static_cast<unsigned char>(mess.id), BINDRESPONSE, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    int bind_data_length = sizeof(bind_data);

    // Make sure bind_response has enough space for bind_data
    memcpy(bind_response, bind_data, bind_data_length );

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
    DEBUG_PRINT("\n-----END OF BIND RES-----");
    send(client_message_header, bind_response, bind_data_length, 0);
}


bool ldap_functions::handleSearchRequest()
{
    DEBUG_PRINT("\n----SEARCH----\n");

    next_byte(client_message_header, 1);

    DEBUG_PRINT(" LDAP Searchreq length is: "<< hex << get_mess_length());
    DEBUG_PRINT_BYTE_CONTENT;

    if(byte_content != 0x04) return 0; // T objectType - octet string

    next_byte(client_message_header, 1);
    int dn_length = get_mess_length();  //L
    
    DEBUG_PRINT("DN length:(dec) " << dec << dn_length);

    // Read the DN based on the DN length
    getDNcontent(dn_length);    //V
    
    DEBUG_PRINT("Distinguished Name: " << dn);

    //getDNcontent already sets next byte
    if(byte_content != 0x0a) return 0; //T
    
    DEBUG_PRINT_BYTE_CONTENT;

    if(!next_byte_content_equals_to(0x01)) return 0;//L

    //baseObject (0): Search only the base object.
    //for THIS PROJECT is enough base 0;

    //singleLevel (1): Search all entries at one level below the base object.
    //wholeSubtree (2): Search the whole subtree rooted at the base object.
    if(!next_byte_content_bigger_than(0x02)) return 0; // V scope - now set to to 2 for testing.
    
    if(!next_byte_content_equals_to(0x0a)) return 0; //T
    
    if(!next_byte_content_equals_to(0x01)) return 0; //L
    
    //dereferenceAliases default = 0 (not implemented by LDAPv2 but still shouldnt come bigger than 3)
    if(!next_byte_content_bigger_than(0x03)) return 0; // V
    //SizeLimit
    if(!next_byte_content_equals_to(ASN_TAG_INTEGER)) return 0; // T SizeLimit

    mess.size_limit = get_limit(); //L,V
    if( mess.size_limit > SIZE_LIMIT || mess.size_limit < 0) return 0; //cant be negative and overreach implemented limit
    DEBUG_PRINT("Size limit: " << dec << mess.size_limit);

    //TimeLimit
    if(byte_content != ASN_TAG_INTEGER) return 0; //T
    mess.time_limit = get_limit(); //L,V
    DEBUG_PRINT("Time limit: " << dec << mess.time_limit);

    //TypesOnly
    if(byte_content != ASN_TAG_BOOL) return 0; //T
    if(!next_byte_content_equals_to(0x01)) return 0; //L
    next_byte(client_message_header, 1); //V
    if (byte_content != 0x00 && byte_content != 0x01) return 0; //bool
    //just checking the correctness, dont need to save it for LDAPv2

    //FILTERS
    get_filter_content();




    return true;
}
