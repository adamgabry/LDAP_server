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

    if (length < 128 ) {
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

/// @brief if lengt is < 128: the length is split into multiple 7-bit chunks and each chunk is added to the LV (Length Value) variable. The LV variable is used to store the encoded length of the message.This code is part of a function that is used to encode the length of a message in a specific format.
/// @param s 
/// @return 
string ldap_functions::LV_string(string s) {
    string LV = "";
    unsigned int length = s.length();

    if (length < 128) 
    {
        LV += static_cast<unsigned char>(length);
    } 
    else 
    {
        // Handle cases where length is greater than or equal to 128
        while (length > 0) 
        {
            unsigned char byte = static_cast<unsigned char>(length & 0x7F);
            length = length >> 7;       
            byte |= 0x80;       // Set the high bit to indicate that more bytes will follow
            LV = string(1, byte) + LV;
        }
    }
    LV += s;
    //for (unsigned char byte : LV) {
    //    cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    //}
    return LV;
}

string ldap_functions::LV_id(int num) 
{
    string result = "";
    int tmp = 0;
    int original_num = num;
    while (num != 0) 
    {
        num = num / 256;
        tmp++;
    }
    num = original_num; // restore the original value of num
    result += static_cast<unsigned char>(tmp);
    for (int i = tmp - 1; i >= 0; i--) //starts from the most significant byte
    {
        unsigned char r = (num >> (i * 8)) & 0xFF; //shifts the required byte into the least significant position and masks off the rest of the bits
        result += r;
    }
    /*
    // Print the result in hexadecimal
    for (unsigned char c : result) 
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    std::cout << std::endl;
    */
    return result;
}
