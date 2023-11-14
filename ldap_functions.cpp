#include "ldap_functions.hpp"


ldap_functions::ldap_functions(int client_socket, set<vector<string>> data)
{
    database = data;
    client_message_header = client_socket;  //just for checking header
    client_message_body = client_socket;    //checking body of message
    byte_index = 0;
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
            next_byte(client_message_header, 1);
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

    debug_print_constructed_response(bind_data_length, bind_response);
    
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
    //DEBUG_PRINT_BYTE_CONTENT;
    if (byte_content != 0x00 && byte_content != 0x01) return 0; //bool
    //just checking the correctness, dont need to save it for LDAPv2

    next_byte(client_message_header, 1); //T

    //FILTERS
    filter = get_filter();

    ///@brief all values that passed the filter
    filters_applied = performSearch(filter);
    
    if(DEBUG)
    {
        for (auto i: filters_applied) {
            if (i.size() >= 3) {
            cout << i[0] << " " << i[1] << " " << i[2] << endl;     
            }
        }
    }

    search_entry();
    search_res_done();

    //clearing the rest of the buffer for memory leaks, because it is used in new thread
    //cin >> client_message_header;
    //cin.ignore(numeric_limits<streamsize>::max(), '\n');

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;
    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;
    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    next_byte(client_message_header, 1); //T
    DEBUG_PRINT_BYTE_CONTENT;

    return true;
}

void ldap_functions::search_entry()
{
    DEBUG_PRINT("\n-----START OF SEARCH RES ENTRY-----\n");

    vector<string> entry = {"cn", "mail"};;
    // Iterate over each filter that was applied
    for (auto filter : filters_applied) {
        string res = "";
        for(int a = 0; a < entry.size(); a++)
        {
            //the newlines are coming from here;
            res += string(1, 0x30) + LV_string(string(1, 0x04) + LV_string(entry[a]) + string(1, 0x31) + LV_string(string(1, 0x04) + LV_string(filter[a])));
        }
        res = string(1, 0x30) + LV_string(string(1, 0x02) + LV_id(mess.id) + string(1, 0x64) + LV_string(string(1, 0x04) + LV_string("uid=" + filter[1]) + string(1, 0x30) + LV_string(res)));
        DEBUG_PRINT("res: " << res);
        send(client_message_header, res.c_str(), res.length(), 0);
    }
}

void ldap_functions::search_res_done()
{
    DEBUG_PRINT("\n-----START OF SEARCH RES DONE-----\n");
    string res = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    res = string(1, 0x30) + LV_string(string(1, 0x02) + LV_id(mess.id) + string(1, 0x65) + LV_string(res));
    DEBUG_PRINT("res: " << res);
    send(client_message_header, res.c_str(), res.length(), 0);
    DEBUG_PRINT("\n-----END OF SEARCH RES DONE-----\n");
}