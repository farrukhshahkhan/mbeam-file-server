CC = gcc
# CFLAGS: Enable warnings, optimization level 2
CFLAGS = -Wall -Wextra -O2
# LDFLAGS: Link with the pthread library
LDFLAGS = -lpthread

TARGET_SERVER = mbeam_file_server
SRC_SERVER = server.c

TARGET_CLIENT = mbeam_client
SRC_CLIENT = client.c

all: $(TARGET_SERVER) $(TARGET_CLIENT)

$(TARGET_SERVER): $(SRC_SERVER)
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) $(SRC_SERVER) $(LDFLAGS)

$(TARGET_CLIENT): $(SRC_CLIENT)
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) $(SRC_CLIENT)

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT) *.bin *.txt

.PHONY: all clean