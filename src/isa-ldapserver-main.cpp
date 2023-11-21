/**
 * @file isa-ldapserver-main.cpp
 * @author Adam Gabrys
 * @login xgabry01
 */

#include "ldap_functions.hpp"
#include "server.hpp"


/// @brief reading the database file and storing it in a set of vectors and starting the server
/// @brief getting arguments from command line
/// @param argc 
/// @param argv 
/// @cite inspired from https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
/// @date of citation 20/10/2023
int main(int argc, char *argv[]) 
{
    string file_name = "";
    int opt;
    int port = 389;
    while ((opt = getopt(argc, argv, "p:f:h:")) != -1) 
    {
        switch (opt) 
        {
            case 'p':
                port = atoi(optarg);
                break;
            case 'f':
                file_name = optarg;
                break;
            case 'h':
                cout << "Usage: " << argv[0] << "./isa-ldapserver {-p <port>} -f <file>" << endl;
                exit(EXIT_SUCCESS);
            default:
                cout << "Argument parse error" << endl;
                exit(EXIT_FAILURE);
        }
    }

    server ldap_server(port);

    cout << "LDAP server is listening on port " << port << "..." << endl;
    
    signal(SIGINT, sigint_handler);

    ldap_server.parse_database(file_name);
    ldap_server.connect_clients();
    
    return 0;
}
