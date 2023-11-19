
// Custom libraries
#include "ldap_functions.hpp"
#include "server.hpp"


void* client_handler(void* arg, set<vector<string>> database) 
{
    int client_socket = *((int*)arg);
    free(arg); // Free the allocated memory
    ldap_functions ldap_start_binding(client_socket, database);
    while(ldap_start_binding.check_ldap_FSM_state()); //while because we want to check all FSM states, and then close the socket
    DEBUG_PRINT("Closing client socket");
    close(client_socket);
}

server::server(int port) 
{

    // Create a socket
    server_socket = socket(AF_INET6, SOCK_STREAM, 0);

    if (server_socket == -1) 
    {
        perror("Error creating socket");
        exit(0);
    }

    int optval = 0;  // allowance of ipv4/6
    setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

    //clear memory
    memset(&server_addr, 0, sizeof(server_addr));

    // Configure the server address structure
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any; // Listen on all interfaces
    server_addr.sin6_port = htons(port); 

    // Bind the socket to the server address
    //
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) 
    {
        perror("Error binding socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    // number of connections that can be waiting while the process is handling a particular connection
    if (listen(server_socket, 5) == -1) //@todo think about the best number of connections
    {
        perror("Error listening");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
}


// Function to parse the database
void server::parse_database(string input_file) 
{
    ifstream infile(input_file);

    if(!infile)
    {
        cout << "Opening the file failed" << endl;
        infile.close();
        exit(EXIT_FAILURE);
    }
    while (getline(infile, line))
    {
        istringstream iss(line);
        if (getline(iss, cn, ';') && getline(iss, uid, ';') && getline(iss, email)) 
        {
            data.clear();
            data.push_back(trim(cn));
            data.push_back(trim(uid));
            data.push_back(trim(email));
            database.emplace(data);
        }
        else
        {
            cout << "Failed to parse the line: " << line << endl;
        }
    }
    //close the file
    infile.close();
}

void server::connect_clients() 
{
    int client_num = 1;
    while (1) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }

        cout << "Client " << client_num << ": Connection accepted from port:" << ":" << ntohs(client_addr.sin6_port) << endl;
        client_num++;

        // Create a new thread to handle the client
        int* client_socket_ptr = (int*)malloc(sizeof(int));
        *client_socket_ptr = client_socket;

        // Start handling the communication with the client in a new thread
        thread(client_handler, client_socket_ptr, database).detach(); // Detach the thread to make it run independently
        //DEBUG_PRINT("Detached thread");
        printf("Client %d: Connection being proccessed\n", client_num - 1);
        // Free the memory allocated for client_socket_ptr
    }
}


/// @brief trims the string
/// @param s 
/// @return 
//@todo remake to make more readable
// https://cplusplus.com/reference/string/string/find_first_of/
// https://cplusplus.com/reference/string/string/find_last_of/
// https://cplusplus.com/reference/string/string/erase/
string server::trim(string s) 
{
    const char* t = " \v\t\n\r\f";
    s.erase(0, s.find_first_not_of(t)); //from pos 0 to first sign
    s.erase(s.find_last_not_of(t) + 1); //from last sign to end

    //test this
    //s.erase(std::remove_if(s.begin(), s.end(), [t](char c) { return std::strchr(t, c) != nullptr; }), s.end());
    return s;
}


int main(int argc, char *argv[]) 
{
    string file_name = "";
    int opt;
    int port = 389;
    while ((opt = getopt(argc, argv, "p:f:")) != -1) 
    {
        switch (opt) 
        {
            case 'p':
                port = atoi(optarg);
                break;
            case 'f':
                file_name = optarg;
                break;
            default:
                cout << "Argument parse error" << endl;
                exit(EXIT_FAILURE);
        }
    }

    server ldap_server(port);

    cout << "LDAP server is listening on port " << port << "..." << endl;
    
    ldap_server.parse_database(file_name);
    ldap_server.connect_clients();
    
    return 0;
}
