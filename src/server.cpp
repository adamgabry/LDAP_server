/**
 * @file server.cpp
 * @author Adam Gabrys
 * @login xgabry01
 */

// Custom libraries
#include "ldap_functions.hpp"
#include "server.hpp"

/// @cite topic: https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
/// @cite answer: https://stackoverflow.com/a/4217052
/// @date of citation 20/10/2023
/// @author Dirk Eddelbuettel
/// @date Nov 18, 2010
/// @param signum 
volatile sig_atomic_t exit_signal = 0;
void sigint_handler(int signum) {
    exit_signal = 1;
}


void client_handler(void* arg, set<vector<string>> database) 
{
    int client_socket = *((int*)arg);
    free(arg); // Free the allocated memory
    ldap_functions ldap_start_binding(client_socket, database);
    while(ldap_start_binding.check_ldap_FSM_state()); //while because we want to check all FSM states, and then close the socket
    DEBUG_PRINT("Closing client socket");
    close(client_socket);
}

/// @cite code snippet in this function inspired from https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp/DemoNonblock/server.c
/// @date 20/10/2023
/// @author Ondrej Rysavy (rysavy@fit.vutbr.cz)
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

/// @cite code snippet in this function inspired from https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp/DemoNonblock/server.c
/// @date 20/10/2023
/// @author Ondrej Rysavy (rysavy@fit.vutbr.cz)
void server::connect_clients() 
{
    int client_num = 1;

    // Set the socket to non-blocking mode
    int flags = fcntl(server_socket, F_GETFL, 0);
    int rc = fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
    if (rc < 0)
    {
        perror("ERROR: fcntl");
        exit(EXIT_FAILURE);								
    }

    while (!exit_signal) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            if (errno == EWOULDBLOCK) {
                // No pending connections, check exit_signal and continue
                continue;
            } else {
                perror("Error accepting connection");
                continue;
            }
        }

        cout << "Client " << client_num << ": Connection accepted from port:" << ":" << ntohs(client_addr.sin6_port) << endl;
        client_num++;

        // Create a new thread to handle the client
        int* client_socket_ptr = (int*)malloc(sizeof(int));
        *client_socket_ptr = client_socket;

        // Start handling the communication with the client in a new thread
        thread(client_handler, client_socket_ptr, database).detach(); // Detach the thread to make it run independently
        printf("Client %d: Connection being proccessed\n", client_num - 1);
    }
    printf("\nClosing server socket\n");
    close(server_socket);
    printf("Server closed and exiting gracefully\n");
}


/// @brief trims the string
/// @param s string to be trimmed
/// @return trimmed string reduced of whitespaces
/// @date of citation 20/10/2023 for all citations in this function
/// @cite inspired by this answer https://stackoverflow.com/q/216823 from topic: https://stackoverflow.com/questions/216823/how-to-trim-a-stdstring
/// @cite https://cplusplus.com/reference/string/string/find_first_of/
/// @cite https://cplusplus.com/reference/string/string/find_last_of/
/// @cite https://cplusplus.com/reference/string/string/erase/
string server::trim(string s) 
{
    const char* t = " \v\t\n\r\f";
    s.erase(0, s.find_first_not_of(t)); //from pos 0 to first sign
    s.erase(s.find_last_not_of(t) + 1); //from last sign to end

    return s;
}
