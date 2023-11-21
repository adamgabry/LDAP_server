/**
 * @file server.hpp
 * @author Adam Gabrys
 * @login xgabry01
 */

// Standard C++ libraries
#include <iostream>
#include <fstream> // Include the necessary header for file operations
#include <cstdlib>
#include <thread>
#include <cstring>
#include <sstream>
#include <string.h>
#include <vector>
#include <set>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <csignal>  // For signal handling

using namespace std; 

/*
* handles more clients at the time
* and calls handleBindRequest function  
*/
void client_handler(void* arg, set<vector<string>> database);

/// @brief creating the SIGINT signal
extern volatile sig_atomic_t exit_signal;

/// @brief Handles the SIGINT signal
extern void sigint_handler(int signum);


class server
{
private:

    /// vars for communication
    ///
    int server_socket,                  //socket for server
        client_socket;                  //socket for client
    struct sockaddr_in6 server_addr,    //server address
                        client_addr;    //client address
    socklen_t client_addr_len = sizeof(client_addr); //length of client address
    pthread_t tid;                      //thread id
    int* client_socket_ptr;             //pointer to client socket

    /// vars for file parsing
    vector<string> data;                //vector of strings for data from csv file
    string  line,                       //line from csv file
            uid,
            cn,
            email;
    set<vector<string>> database;       //the whole database

public:
    /**
    *@brief here is established server itself
    */
    server(int port);
    /**
    *@brief for creating threads and establishing connection with clients
    */
    void connect_clients();
    /**
    *@brief data from csv file
    */
    void parse_database(string input_file);
    /**
    *@brief the string of whitespaces
    */
    string trim(string s);
};