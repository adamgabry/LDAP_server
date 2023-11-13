
#include "ldap_functions.hpp"


/*
ldap_filter ldap_functions::get_filter() {
    ldap_filter filter;
    filter.filter_type = byte_content;
    next_byte(client_message_header, 1);
    filter.filter_length = get_mess_length();
    DEBUG_PRINT("filter length: " << filter.filter_length);
    switch (filter.filter_type)
    {
    case AND:
        DEBUG_PRINT("AND");
        while (byte_index < filter.filter_length)
        {
            filter.filters.push_back(get_filter());
        }
        break;
    case OR:
        DEBUG_PRINT("OR");
        while (byte_index < filter.filter_length)
        {
            filter.filters.push_back(get_filter());
        }
        break;
    case NOT:
        DEBUG_PRINT("NOT");
        while (byte_index < filter.filter_length)
        {
            filter.filters.push_back(get_filter());
        }
        break;
    case EQUALITY_MATCH:
        DEBUG_PRINT("EQUALITY_MATCH");
        filter.a = "";
        next_byte(client_message_header, 1);
        for (int i = 0; i < filter.filter_length - 1; i++)
        {
            filter.a += byte_content;
            next_byte(client_message_header, 1);
        }
        DEBUG_PRINT("filter content: " << filter.a);
        break;
    case SUBSTRING:
        DEBUG_PRINT("SUBSTRING");
        filter.a = "";
        next_byte(client_message_header, 1);
        for (int i = 0; i < filter.filter_length - 1; i++)
        {
            filter.a += byte_content;
            next_byte(client_message_header, 1);
        }
        DEBUG_PRINT("filter content: " << filter.a);
        break;
    default:
        DEBUG_PRINT("default");
        break;
    }
    return filter;
    // Access functions and perform operations...
    return filter;
}
*/
Filter ldap_functions::get_filter_content(){
    next_byte(client_message_header, 1);
    DEBUG_PRINT_BYTE_CONTENT;
    return filter;
}