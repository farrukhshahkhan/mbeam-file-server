#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <endian.h> // For htobe64, be64toh
#include "mbeam.h"  // our common definitions

// Helper function to read exactly n bytes from a socket (same as server)
ssize_t read_exact(int sockfd, void *buf, size_t n) {
    size_t bytes_read = 0;
    ssize_t result;
    while (bytes_read < n) {
        result = read(sockfd, (char *)buf + bytes_read, n - bytes_read);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1; // Error
        } else if (result == 0) {
            return 0; // Connection closed
        }
        bytes_read += result;
    }
    return bytes_read;
}

void print_progress(uint64_t current, uint64_t total) {
    if (total == 0) return;
    double percentage = (double)current / total * 100.0;
    printf("\rProgress: %5.2f%% (%lu/%lu bytes)", percentage, current, total);
    fflush(stdout);
}

void download_file(const char *server_ip, const char *filename, const char *output_filename) {
    int sockfd;
    struct sockaddr_in server_addr;
    uint64_t offset = 0;
    struct stat st;

    // 1. Determine offset for resumption if last time file was partially downloaded
    if (stat(output_filename, &st) == 0) {
        offset = st.st_size;
        printf("Local file found. Attempting to resume from offset: %lu\n", offset);
    }

    // 2. Connect to server
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return;
    }

    // 3. Send Request
    // Request format: [Filename Length (2B)] [Filename (V)] [Offset (8B)]

    // 3a. Send Filename Length
    uint16_t filename_len = strlen(filename);
    uint16_t network_filename_len = htons(filename_len);
    if (write(sockfd, &network_filename_len, sizeof(network_filename_len)) != sizeof(network_filename_len)) {
        perror("Error sending filename length");
        goto cleanup;
    }

    // 3b. Send Filename
    if (write(sockfd, filename, filename_len) != filename_len) {
        perror("Error sending filename");
        goto cleanup;
    }

    // 3c. Send Offset
    // Convert offset to Network Byte Order (Big Endian)
    uint64_t network_offset = htobe64(offset);
    if (write(sockfd, &network_offset, sizeof(network_offset)) != sizeof(network_offset)) {
        perror("Error sending offset");
        goto cleanup;
    }

    // 4. Receive Response Header
    // Response format: [Status (1B)] [Total File Size (8B)] [Data (V)]
    uint8_t status;
    uint64_t network_file_size;

    if (read_exact(sockfd, &status, sizeof(status)) <= 0) {
        printf("Error reading status from server.\n");
        goto cleanup;
    }

    if (read_exact(sockfd, &network_file_size, sizeof(network_file_size)) <= 0) {
        printf("Error reading file size from server.\n");
        goto cleanup;
    }

    // Convert file size from Network Byte Order to Host Byte Order
    uint64_t file_size = be64toh(network_file_size);

    // 5. Handle Response Status
    switch (status) {
        case STATUS_OK:
            printf("Server response OK. Total file size: %lu bytes.\n", file_size);
            break;
        case STATUS_NOT_FOUND:
            printf("Error: File not found on server.\n");
            goto cleanup;
        case STATUS_ACCESS_DENIED:
            printf("Error: Access denied by server (Security violation).\n");
            goto cleanup;
        case STATUS_ERROR:
        default:
            printf("Error: Server reported an internal error or invalid offset.\n");
            goto cleanup;
    }

    // This error should not happen unless the file on client is from a different download
    if (offset > file_size) {
        printf("Error: Local file is larger than server file. Cannot resume.\n");
        goto cleanup;
    }

    if (file_size == 0) {
        printf("File is empty.\n");
        // Create an empty file
        int fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd != -1) close(fd);
        goto cleanup;
    }

    if (offset == file_size) {
        printf("File already fully downloaded.\n");
        goto cleanup;
    }

    // 6. Open local file
    // Use O_APPEND if resuming, otherwise O_TRUNC (truncate)
    int fd = open(output_filename, O_WRONLY | O_CREAT | (offset > 0 ? O_APPEND : O_TRUNC), 0644);
    if (fd == -1) {
        perror("Error opening local file for writing");
        goto cleanup;
    }

    // 7. Receive file data
    char buffer[BUFFER_SIZE];
    uint64_t bytes_received = offset;
    ssize_t bytes_read;

    print_progress(bytes_received, file_size);

    while (bytes_received < file_size) {
        // Calculate how much to read in this iteration
        size_t remaining = file_size - bytes_received;
        size_t read_size = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;

        bytes_read = read(sockfd, buffer, read_size);

        if (bytes_read < 0) {
            perror("\nError receiving data");
            break;
        } else if (bytes_read == 0) {
            printf("\nConnection closed by server prematurely.\n");
            break;
        }

        if (write(fd, buffer, bytes_read) != bytes_read) {
            perror("\nError writing to local file");
            break;
        }

        bytes_received += bytes_read;
        print_progress(bytes_received, file_size);
    }

    printf("\n");

    if (bytes_received == file_size) {
        printf("Download complete.\n");
    } else {
        printf("Download incomplete.\n");
    }

    close(fd);

cleanup:
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <server_ip> <remote_filename> <local_output_filename>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    const char *filename = argv[2];
    const char *output_filename = argv[3];

    download_file(server_ip, filename, output_filename);

    return 0;
}