#include <iostream>
#include <cstdlib>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#define ERR 1

using namespace std; 

/*
* handles more clients at the time
* and calls handleBindRequest function  
*/
void* client_handler(void* arg, set<vector<string>> database);


class server
{
private:

    /// vars for communication
    ///
    int server_socket, 
        client_socket;
    struct sockaddr_in  server_addr,
                        client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t tid;
    int* client_socket_ptr;
    ///
    
    /// vars for file parsing
    ///
    vector<string> data;
    string  line,
            uid,
            cn,
            email;
    set<vector<string>> database;

public:
    /*
    *@brief here is established server itself
    */
    server(int port);
    /*
    *@brief for creating threads and establishing connection with clients
    */
    void connect_clients();
    /*
    *parsing data from csv file
    */
    void parse_database(string input_file);

    string trim(string s);
};