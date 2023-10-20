# Makefile for your C program

# Compiler and compiler flags
CC = gcc
CFLAGS = -Wall -g

# Source file and output executable name
SOURCE = server.c ldap_functions.c
OUTPUT = server
BEHAVIOR = -lpthread

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCE) $(BEHAVIOR)

clean:
	rm -f $(OUTPUT)