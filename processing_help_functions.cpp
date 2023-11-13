#include "ldap_functions.hpp"

using namespace std;

void ldap_functions::next_byte(int client_message,size_t amount){
    read(client_message,&byte_content, amount); //read one byte
    byte_index += amount;
    //DEBUG_PRINT("bytes read: " << dec << byte_index);
} 

int ldap_functions::next_byte_content_equals_to(int hex_value)
{
    next_byte(client_message_header, 1);
    DEBUG_PRINT_BYTE_CONTENT;
    if(byte_content != hex_value) return 0;
    return 1;
}

int ldap_functions::this_byte_content_equals_to(int hex_value)
{
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

//MAY NOT BE CORRECT FOR LONGER THAN 0x80
///@brief when returning from this function, sets already next byte to the buffer!
int ldap_functions::get_mess_length() {
    int length = 0;
    length = byte_content & 0x7F;  // Initialize with the low 7 bits of the first byte
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

void ldap_functions::debug_print_constructed_response(int bind_data_length, char* bind_response)
{
    if(DEBUG)
    {
        DEBUG_PRINT("BindResponse length: "<< dec << bind_data_length << "\nSent BindResponse to the client:");
        
        for (int i = 0; i < bind_data_length; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bind_response[i] << " ";
        }
        std::cout << std::endl;
    }
}