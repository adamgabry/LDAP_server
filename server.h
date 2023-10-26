#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

/*
* handles more clients at the time.
*/
void* client_handler(void* arg);


class server
{
private:
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int* client_socket_ptr;
public:
    server(int port);

    void connect_clients();
    
};
