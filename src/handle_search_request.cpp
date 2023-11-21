/**
 * @file handle_search_request.cpp
 * @author Adam Gabrys
 * @login xgabry01
 * 
 */

#include "ldap_functions.hpp"

bool ldap_functions::handleSearchRequest()
{
    DEBUG_PRINT("\n----SEARCH START----\n");

    next_byte(client_message_header, 1);

    int searchreq_length = get_mess_length();

    DEBUG_PRINT(" LDAP Searchreq length is: "<< hex << searchreq_length);

    if(!this_byte_content_equals_to(ASN_TAG_OCTETSTRING)) return 0; // T objectType - octet string

    next_byte(client_message_header, 1);

    int base_content_length = get_mess_length();  //L
    
    DEBUG_PRINT("DN length:(dec) " << dec << base_content_length);

    // Read the DN based on the DN length
    get_base_content(base_content_length);    //V
    
    DEBUG_PRINT("Distinguished Name: " << dn); 

    DEBUG_PRINT_BYTE_CONTENT;

    //getDNcontent already sets next byte
    if(!this_byte_content_equals_to(ASN_TAG_ENUMERATED)) return 0; //T

    if(!next_byte_content_equals_to(0x01)) return 0;//L

    //for THIS PROJECT is enough base 0;
    //baseObject (0): Search only the base object.
    //singleLevel (1): Search all entries at one level below the base object.
    //wholeSubtree (2): Search the whole subtree rooted at the base object.
    if(!next_byte_content_bigger_than(0x02)) return 0; // V scope - now set to to 2 for testing.
    
    if(!next_byte_content_equals_to(ASN_TAG_ENUMERATED)) return 0; //T
    
    if(!next_byte_content_equals_to(0x01)) return 0; //L
    
    //dereferenceAliases default = 0 (not implemented by LDAPv2 but still shouldnt come bigger than 3)
    if(!next_byte_content_bigger_than(0x03)) return 0; // V
    
    if(!next_byte_content_equals_to(ASN_TAG_INTEGER)) return 0; // T SizeLimit

    //SizeLimit
    mess.size_limit = get_limit(); //L,V
    if(mess.size_limit == 0)
    {
        mess.size_limit = SIZE_LIMIT;
    }
    //cant be negative and overreach implemented limit
    if( mess.size_limit > SIZE_LIMIT )
    {
     sendSizeLimitExceededMessage();
     return 0;   
    }
    DEBUG_PRINT("Size limit: " << dec << mess.size_limit);

    //TimeLimit
    if(!this_byte_content_equals_to(ASN_TAG_INTEGER)) return 0; //T

    int time_limit = get_limit(); //L,V
    DEBUG_PRINT("Time limit: " << dec << time_limit);

    //TypesOnly
    if(!this_byte_content_equals_to(ASN_TAG_BOOL)) return 0; //T

    if(!next_byte_content_equals_to(0x01)) return 0; //L
    
    next_byte(client_message_header, 1); //V
    //just checking the correctness, dont need to save it for LDAPv2
    if (byte_content != 0x00 && byte_content != 0x01) return 0; //bool

    next_byte(client_message_header, 1); //T

    //FILTERS
    filter = get_filter();

    ///@brief all values that passed the filter
    filters_applied = performSearch(filter);
    
    #ifdef DEBUG
    {
        for (auto i: filters_applied) {
            if (i.size() >= 3) {
            cout << i[0] << " " << i[1] << " " << i[2] << endl;     
            }
        }
    }
    #endif

    search_entry();
    if(mess.size_limit_exceeded) return 0;

    search_res_done();

    //rest of the attributesDescriptors
    if(!this_byte_content_equals_to(BER_TAG_SEQUENCE)) return 0; //T

    next_byte(client_message_header, 1);
    
    int attr_length = get_mess_length(); //L

    //emptying the rest of the message
    for(int i = 0; i < attr_length - 1; i++)
    {
        next_byte(client_message_header, 1);
        DEBUG_PRINT_BYTE_CONTENT;
    }

    return 1; 
}

