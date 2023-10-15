# Makefile for your C program

# Compiler and compiler flags
CC = gcc
CFLAGS = -Wall -g

# Source file and output executable name
SOURCE = server.c
OUTPUT = server

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCE)

clean:
	rm -f $(OUTPUT)