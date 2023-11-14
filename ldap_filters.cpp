
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

case SUBSTRING:
        DEBUG_PRINT("SUBSTRING");
        filter.attr_desc = "";
        filter.attr_value = "";
        if (!this_byte_content_equals_to(ASN_TAG_OCTETSTRING)) return filter;

        // Parse attribute description
        next_byte(client_message_header, 1);
        filter.attr_desc_length = get_mess_length();
        DEBUG_PRINT("attr_desc_length: " << filter.attr_desc_length);

        for (int i = 0; i < filter.attr_desc_length; i++, next_byte(client_message_header, 1))
        {
            filter.attr_desc += byte_content;
        }
        DEBUG_PRINT("attr_value: " << filter.attr_desc);

        // Parse substring elements
        DEBUG_PRINT_BYTE_CONTENT;
        if(!this_byte_content_equals_to(BER_TAG_SEQUENCE)) return filter; //T
        next_byte(client_message_header, 1);
        filter.attr_value_length = get_mess_length(); //L

        while(filter.attr_value_length > 0)
        {
            unsigned tmp = byte_content; // T unsigned so it can hold up to 255 
            next_byte(client_message_header, 1); 
            int tmp_length = get_mess_length(); // L
            string string_to_add = get_string(tmp_length); // V
            DEBUG_PRINT("string_to_add: " << string_to_add);
            switch (tmp)
            {
                case FILTER_INITIAL:
                    DEBUG_PRINT("FILTER_INITIAL");
                    filter.attr_value += string_to_add + FILTER_ANY_SIGN;
                    break;
                case FILTER_ANY:
                    DEBUG_PRINT("FILTER_ANY");
                    filter.attr_value += FILTER_ANY_SIGN + string_to_add + FILTER_ANY_SIGN;
                    break;
                case FILTER_FINAL:
                    DEBUG_PRINT("FILTER FINAL");
                    filter.attr_value += FILTER_ANY_SIGN + string_to_add;
                default:
                    return filter;
            }
            filter.attr_value_length -= tmp_length + 2; // 2 = T + L
        } 

        DEBUG_PRINT("filter content: " << filter.attr_value);
        break;

        default:
            DEBUG_PRINT("default");
            break;
        }
    return filter;
    // Access functions and perform operations...
}

set<vector<string>> ldap_functions::performSearch(Filter f) 
{
    set<vector<string>> result;
    DEBUG_PRINT("\n---performSearch---\n");
    if(f.filter_type == EQUALITY_MATCH){
        DEBUG_PRINT("database size: " << database.size());
        for (auto entry : database) 
        {
            DEBUG_PRINT("entry: " << entry[1]);
            // Check if the attributeDesc matches the entry's attribute
            if (entry.size() > 1 && entry[1] == f.attr_value) 
            {
                DEBUG_PRINT("got here");
                vector<string> entry_vec;
                for (auto& e : entry) 
                {
                    entry_vec.emplace_back(e);
                }
                result.insert(entry_vec);  
            }
        }
    }
    if(f.filter_type == SUBSTRING)
    {
        DEBUG_PRINT("database size: " << database.size());
        for (auto entry : database) 
        {
            DEBUG_PRINT("entry: " << entry[1]);
            // Check if the attributeDesc matches the entry's attribute
            if (entry.size() > 1) 
            {
                std::regex pattern(f.attr_value);
                if (std::regex_search(entry[1], pattern))
                {
                    vector<string> entry_vec;
                    for (auto& e : entry) 
                    {
                        entry_vec.emplace_back(e);
                    }
                    result.insert(entry_vec);  
                }
            }
        }
    }
    DEBUG_PRINT("result size: " << result.size());
    return result;
}