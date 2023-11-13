
#include "ldap_functions.hpp"


Filter ldap_functions::get_filter() {
    Filter filter;

    DEBUG_PRINT("---ENTERING FILTER---");
    DEBUG_PRINT_BYTE_CONTENT;

    filter.filter_type = byte_content;

    if (filter.filter_type != AND &&
        filter.filter_type != OR &&
        filter.filter_type != NOT &&
        filter.filter_type != EQUALITY_MATCH &&
        filter.filter_type != SUBSTRING) 
    {
        DEBUG_PRINT("filter type is not correct");
        return filter;
    }
    next_byte(client_message_header, 1);
    filter.filter_length = get_mess_length();
    DEBUG_PRINT("filter length: " << filter.filter_length);

    switch (filter.filter_type)
    {
    case EQUALITY_MATCH:
        DEBUG_PRINT("EQUALITY_MATCH");
        filter.attr_desc = "";
        filter.attr_value = "";

        if(!this_byte_content_equals_to(ASN_TAG_OCTETSTRING)) return filter;

        next_byte(client_message_header, 1);
        filter.attr_desc_length = get_mess_length();
        DEBUG_PRINT("attr_desc_length: " << filter.attr_desc_length);

        for (int i = 0; i < filter.attr_desc_length; i++, next_byte(client_message_header, 1))
        {
            filter.attr_desc += byte_content;
            //DEBUG_PRINT("atr_desc: " << filter.attr_desc);
            //DEBUG_PRINT_BYTE_CONTENT;
        }

        if(!this_byte_content_equals_to(ASN_TAG_OCTETSTRING)) return filter;
        next_byte(client_message_header, 1);
        filter.attr_value_length = get_mess_length();
        DEBUG_PRINT("attr_value_length: " << filter.attr_value_length);

        for(int i = 0; i < filter.attr_value_length; i++, next_byte(client_message_header, 1))
        {
            filter.attr_value += byte_content;
            //DEBUG_PRINT_BYTE_CONTENT;
        }
        DEBUG_PRINT("atr_value: " << filter.attr_desc);
        DEBUG_PRINT("filter content: " << filter.attr_value);
        break;

   /* case SUBSTRING:
        DEBUG_PRINT("SUBSTRING");
        filter.value = "";
        next_byte(client_message_header, 1);
        for (int i = 0; i < filter.filter_length - 1; i++)
        {
            filter.value += byte_content;
            next_byte(client_message_header, 1);
        }
        DEBUG_PRINT("filter content: " << filter.value);
        break;
        */
        default:
            DEBUG_PRINT("default");
            break;
        }
    return filter;
    // Access functions and perform operations...
}
/*
set<vector<string>> performSearch(Filter f) {
    vector<string> result;
    if(f.filter_type == EQUALITY_MATCH){
        for (const auto entry : database) {
            // Check if the attributeDesc matches the entry's attribute
            if (entry.size() > 1 && entry[1] == f.attr_desc) {
                // Check if the assertionValue matches the entry's value
                if (entry.size() > 2 && entry[2] == assertionValue) {
                    result.push_back(entry);
                }
            }
        }
    }
    return result;
}
*/