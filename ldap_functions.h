#ifndef LDAP_FUNCTIONS_H
#define LDAP_FUNCTIONS_H

#include <iostream>
#include <cstring>
#include <string.h>
#include <vector>
#include <set>
#include <unistd.h>
#include <iomanip> 
#include <sys/socket.h>
#include "ldap_functions.h"

#define PORT 389
#define DEBUG 1

using namespace std;

//macro for DEBUG printing
#ifdef DEBUG
    #define DEBUG_PRINT(message) std::cout << message << std::endl
    #else
    #define DEBUG_PRINT(message) // Define as nothing when debugging is disabled
#endif

void sendBindResponse(int client_socket);
void handleBindRequest(int client_socket, set<vector<string>> database);

#endif
