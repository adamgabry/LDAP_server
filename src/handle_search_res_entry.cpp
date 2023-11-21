/**
 * @file handle_search_res_entry.cpp
 * @author Adam Gabrys
 * @login xgabry01
 */

#include "ldap_functions.hpp"

/**
 * @brief This function is responsible for searching and handling search result entries.
 * 
 * It iterates over each filter that was applied and sends the search result entry to the client.
 * If the number of entries exceeds the size limit, it sends item size limit exceeded message to the client.
 */
void ldap_functions::search_entry()
{
    DEBUG_PRINT("\n-----START OF SEARCH RES ENTRY-----\n");

    vector<string> entry = {"cn", "uid", "mail"};
    int entry_length = entry.size();
    int num_of_entries = 0;

    // Iterate over each filter that was applied
    for (auto filter : filters_applied) {
        if(num_of_entries == mess.size_limit)
        {
            mess.size_limit_exceeded = true;
            sendSizeLimitExceededMessage();
            return;
        }
        string res = "";
        for(int item = 0; item < entry_length; item++)
        {
            if(item != 1) //skip sending uid
            {
            res += "\x30" + LV_string("\x04" + LV_string(entry[item]) + "\x31" + LV_string("\x04" + LV_string(filter[item])));}
        }
        res = LDAP_PACKET_STRING + LV_string("\x02" + LV_id(mess.id) + SEARCHRESENTRY_STRING + LV_string("\x04" + LV_string("uid=" + filter[1]) + '\x30' + LV_string(res)));
        DEBUG_PRINT("res: " << res);

        send(client_message_header, res.c_str(), res.length(), 0);
        num_of_entries++;
    }
}
