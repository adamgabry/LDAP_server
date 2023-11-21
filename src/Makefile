CC = g++
CFLAGS = -Wall -g

SOURCES = server.cpp ldap_functions.cpp ldap_filters.cpp processing_help_functions.cpp handle_search_request.cpp handle_search_res_done.cpp handle_search_res_entry.cpp isa-ldapserver-main.cpp

# Generate object file names from source
OBJECTS = $(SOURCES:.cpp=.o)

# Output binary name (should not include the file extension)
TARGET = isa-ldapserver

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) -lpthread

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)