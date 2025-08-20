#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <endian.h> // For htobe64, be64toh
#include "mbeam.h"  // our common definistion

#define MAX_BACKLOG 10  // listen() function que size

// Global variable to store the canonicalized server root path
char resolved_server_root[PATH_MAX];    // PATH_MAX is coming from limits.h

// Structure to pass data to threads
typedef struct {
    int sockfd;
    struct sockaddr_in addr;
} client_info_t;

// Helper function to read exactly n bytes from a socket
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

// Function to handle the file transfer logic
void process_request(int sockfd, uint64_t offset, const char *filename) {
    char filepath[PATH_MAX];
    char resolved_path[PATH_MAX];
    struct stat st;
    int fd = -1;
    uint8_t status = STATUS_ERROR;
    uint64_t file_size = 0;

    // 1. Construct initial path
    // Prevent absolute path requests
    if (filename[0] == '/') {
        syslog(LOG_WARNING, "Absolute path requested: %s", filename);
        status = STATUS_ACCESS_DENIED;
        goto send_response;
    }
    // Make sure path and filename don't overrun the PATH_MAX system limit.
    if (strlen(SERVER_ROOT)+strlen(filename)+2 >= PATH_MAX) {
        syslog(LOG_ERR, "File path too long.");
        status = STATUS_ERROR;
        goto send_response;
    }
    else {
        snprintf(filepath, sizeof(filepath), "%s/%s", SERVER_ROOT, filename);
    }

    // 2. Security Check: Resolve path and verify it's within SERVER_ROOT
    // realpath() canonicalizes the path (resolves '..' and symlinks)
    if (realpath(filepath, resolved_path) == NULL) {
        if (errno == ENOENT) {
            syslog(LOG_INFO, "File not found: %s", filepath);
            status = STATUS_NOT_FOUND;
        } else {
            syslog(LOG_ERR, "Error resolving path %s: %s", filepath, strerror(errno));
            status = STATUS_ERROR;
        }
        goto send_response;
    }

    // Verify the resolved path starts with the resolved server root
    if (strncmp(resolved_server_root, resolved_path, strlen(resolved_server_root)) != 0) {
        syslog(LOG_WARNING, "Directory traversal attempt detected: %s resolved to %s", filename, resolved_path);
        status = STATUS_ACCESS_DENIED;
        goto send_response;
    }

    // 3. Get file stats and open file
    if (stat(resolved_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        syslog(LOG_INFO, "Path is not a regular file: %s", resolved_path);
        status = STATUS_NOT_FOUND; // Treat directories/special files as not found
        goto send_response;
    }

    file_size = st.st_size;

    // Check requested offset
    if (offset > file_size) {
        syslog(LOG_ERR, "Invalid offset requested: %lu > %lu", offset, file_size);
        status = STATUS_ERROR;
        goto send_response;
    }

    fd = open(resolved_path, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "Error opening file %s: %s", resolved_path, strerror(errno));
        status = STATUS_ERROR;
        goto send_response;
    }

    status = STATUS_OK;

send_response:
    // 4. Send Response Header (Status + File Size)
    // Convert file size to Network Byte Order (Big Endian)
    uint64_t network_file_size = htobe64(file_size);
    
    // Combine status and file size into a single header buffer
    char header[sizeof(status) + sizeof(network_file_size)];
    memcpy(header, &status, sizeof(status));
    memcpy(header + sizeof(status), &network_file_size, sizeof(network_file_size));

    // Send the header
    if (write(sockfd, header, sizeof(header)) != sizeof(header)) {
        syslog(LOG_ERR, "Failed to send response header: %s", strerror(errno));
        if (fd != -1) close(fd);
        return;
    }

    if (status != STATUS_OK || file_size == 0 || offset == file_size) {
        if (fd != -1) close(fd);
        return;
    }

    // 5. Transfer file content using sendfile() (Zero-Copy Optimization)
    syslog(LOG_INFO, "Starting transfer of %s from offset %lu", resolved_path, offset);
    off_t send_offset = (off_t)offset;
    ssize_t sent_bytes;
    uint64_t remaining_bytes = file_size - offset;

    // sendfile copies data directly from file descriptor to socket descriptor in kernel space
    while (remaining_bytes > 0) {
        sent_bytes = sendfile(sockfd, fd, &send_offset, remaining_bytes);

        if (sent_bytes <= 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            // Since SIGPIPE is ignored, sendfile returns -1 and sets errno (e.g., EPIPE) if the client disconnects.
            syslog(LOG_WARNING, "sendfile failed (client disconnected?): %s. Transferred %lu/%lu bytes.",
                   strerror(errno), (uint64_t)send_offset, file_size);
            close(fd);
            return;
        }
        remaining_bytes -= sent_bytes;
        // sendfile automatically updates send_offset
    }

    syslog(LOG_INFO, "File transfer completed successfully for %s.", resolved_path);
    close(fd);
}


// Thread function to handle a client connection
void *handle_client(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    int sockfd = client_info->sockfd;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_info->addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_info->addr.sin_port);

    syslog(LOG_INFO, "Connection established with %s:%d", client_ip, client_port);
    free(client_info); // Free the structure allocated in the main loop

    // --- Protocol Implementation ---
    // Request format: [Filename Length (2B)] [Filename (V)] [Offset (8B)]

    // 1. Read Filename Length (2 bytes)
    uint16_t network_filename_len;
    if (read_exact(sockfd, &network_filename_len, sizeof(network_filename_len)) <= 0) {
        syslog(LOG_ERR, "Error reading filename length from %s:%d", client_ip, client_port);
        goto cleanup;
    }
    uint16_t filename_len = ntohs(network_filename_len);

    if (filename_len == 0 || filename_len > MAX_FILENAME_LEN) {
        syslog(LOG_ERR, "Invalid filename length received: %d.", filename_len);
        goto cleanup;
    }

    // 2. Read Filename (variable bytes)
    char filename[MAX_FILENAME_LEN + 1];
    if (read_exact(sockfd, filename, filename_len) <= 0) {
        syslog(LOG_ERR, "Error reading filename from %s:%d", client_ip, client_port);
        goto cleanup;
    }
    filename[filename_len] = '\0'; // Null-terminate the string

    // 3. Read Offset (8 bytes)
    uint64_t network_offset;
    if (read_exact(sockfd, &network_offset, sizeof(network_offset)) <= 0) {
        syslog(LOG_ERR, "Error reading offset from %s:%d", client_ip, client_port);
        goto cleanup;
    }
    // Convert from Network Byte Order (Big Endian) to Host Byte Order
    uint64_t offset = be64toh(network_offset);

    syslog(LOG_INFO, "Client %s:%d requested file: %s, offset: %lu", client_ip, client_port, filename, offset);

    // Process the request and send the file
    process_request(sockfd, offset, filename);

cleanup:
    close(sockfd);
    syslog(LOG_INFO, "Connection closed with %s:%d", client_ip, client_port);
    return NULL;
}

void initialize_server(char *server_name) {
    // Initialize logging
    openlog(server_name, LOG_PID | LOG_CONS, LOG_USER);

    // Ensure the server root directory exists
    mkdir(SERVER_ROOT, 0755);

    // Resolve the server root path for security checks
    if (realpath(SERVER_ROOT, resolved_server_root) == NULL) {
        syslog(LOG_ERR, "Failed to resolve SERVER_ROOT (%s): %s. Ensure the directory exists and has correct permissions.", SERVER_ROOT, strerror(errno));
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "Server root initialized at: %s", resolved_server_root);

    // Ignore SIGPIPE. This prevents the server from crashing if a client disconnects 
    // unexpectedly while the server is writing (e.g., during sendfile).
    signal(SIGPIPE, SIG_IGN);
}

int main(int argc, char *argv[]) {
    int server_fd;
    struct sockaddr_in server_addr;
    pthread_t tid;

    if (argc > 1) {
        fprintf(stderr, "Unknown arguments to server passed\n");
        exit(EXIT_FAILURE);
    }
    initialize_server(argv[0]);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Set socket options (allow address reuse)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, MAX_BACKLOG) < 0) {
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Server started. Listening on port %d...", PORT);
    printf("Server listening on port %d. Check syslog for details.\n", PORT);

    // Main accept loop
    while (1) {
        // Allocate memory for client info on the heap to safely pass to the thread
        client_info_t *client_info = malloc(sizeof(client_info_t));
        if (!client_info) {
            syslog(LOG_ERR, "Failed to allocate memory for client info.");
            continue;
        }

        socklen_t addr_len = sizeof(client_info->addr);

        // Accept connection
        if ((client_info->sockfd = accept(server_fd, (struct sockaddr *)&client_info->addr, &addr_len)) < 0) {
            syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
            free(client_info);
            continue;
        }

        // Create a new thread to handle the client
        if (pthread_create(&tid, NULL, handle_client, (void *)client_info) != 0) {
            syslog(LOG_ERR, "Thread creation failed: %s", strerror(errno));
            close(client_info->sockfd);
            free(client_info);
        }

        // Detach the thread so resources are released automatically when it finishes
        pthread_detach(tid);
    }

    closelog();
    close(server_fd);
    return 0;
}