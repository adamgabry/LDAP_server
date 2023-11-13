CC = g++
CFLAGS = -Wall -g

# Add your source files here
SOURCES = server.cpp ldap_functions.cpp ldap_filters.cpp processing_help_functions.cpp

# Generate object file names from source files
OBJECTS = $(SOURCES:.cpp=.o)

# Output binary name (should not include the file extension)
TARGET = server

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) -lpthread

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
 
 #version for c 
 # Makefile for your C program

# Compiler and compiler flags
#CC = gcc
#CFLAGS = -Wall -g

# Source file and output executable name
#SOURCE = server.c ldap_functions.c
#OUTPUT = server
#BEHAVIOR = -lpthread

#all: $(OUTPUT)

#$(OUTPUT): $(SOURCE)
#	$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCE) $(BEHAVIOR)
#
#clean:
#	rm -f $(OUTPUT)
