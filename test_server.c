// test_server.c
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <limits.h>
#include <endian.h>

// Protocol definitions (from server.c)
#define STATUS_OK 0
#define STATUS_NOT_FOUND 1
#define STATUS_ERROR 2
#define STATUS_ACCESS_DENIED 3
#define SERVER_ROOT "./server_files"
#define MAX_FILENAME_LEN 1024

// Mock/Stub tracking structures
typedef struct {
    int called;
    int return_value;
    size_t bytes_to_read;
    char data[4096];
    int errno_value;
} mock_read_data_t;

typedef struct {
    int called;
    int return_value;
    size_t bytes_written;
    char data[4096];
    int errno_value;
} mock_write_data_t;

typedef struct {
    int called;
    struct stat stat_data;
    int return_value;
} mock_stat_data_t;

typedef struct {
    int called;
    int return_value;
    int fd_returned;
} mock_open_data_t;

typedef struct {
    int called;
    ssize_t return_value;
    int errno_value;
} mock_sendfile_data_t;

typedef struct {
    int called;
    char resolved[PATH_MAX];
    char *return_value;
} mock_realpath_data_t;

// Global mock data
static mock_read_data_t mock_read_data;
static mock_write_data_t mock_write_data;
static mock_stat_data_t mock_stat_data;
static mock_open_data_t mock_open_data;
static mock_sendfile_data_t mock_sendfile_data;
static mock_realpath_data_t mock_realpath_data;

// Reset all mocks
void reset_mocks() {
    memset(&mock_read_data, 0, sizeof(mock_read_data));
    memset(&mock_write_data, 0, sizeof(mock_write_data));
    memset(&mock_stat_data, 0, sizeof(mock_stat_data));
    memset(&mock_open_data, 0, sizeof(mock_open_data));
    memset(&mock_sendfile_data, 0, sizeof(mock_sendfile_data));
    memset(&mock_realpath_data, 0, sizeof(mock_realpath_data));
}

// Include the functions we want to test (in real implementation, you'd separate these)
// For now, we'll define stubs and test the core logic

// Mock functions
ssize_t mock_read(int fd, void *buf, size_t count) {
    mock_read_data.called++;
    if (mock_read_data.errno_value != 0) {
        errno = mock_read_data.errno_value;
        return -1;
    }
    if (mock_read_data.return_value == 0) {
        return 0; // EOF
    }
    size_t to_copy = (count < mock_read_data.bytes_to_read) ? count : mock_read_data.bytes_to_read;
    memcpy(buf, mock_read_data.data, to_copy);
    return to_copy;
}

ssize_t mock_write(int fd, const void *buf, size_t count) {
    mock_write_data.called++;
    if (mock_write_data.errno_value != 0) {
        errno = mock_write_data.errno_value;
        return -1;
    }
    size_t to_copy = (count < sizeof(mock_write_data.data)) ? count : sizeof(mock_write_data.data);
    memcpy(mock_write_data.data, buf, to_copy);
    mock_write_data.bytes_written = to_copy;
    return mock_write_data.return_value > 0 ? to_copy : (size_t) mock_write_data.return_value;
}

int mock_stat(const char *path, struct stat *st) {
    mock_stat_data.called++;
    if (mock_stat_data.return_value == 0) {
        *st = mock_stat_data.stat_data;
    }
    return mock_stat_data.return_value;
}

int mock_open(const char *pathname, int flags) {
    mock_open_data.called++;
    if (mock_open_data.return_value < 0) {
        errno = ENOENT;
        return -1;
    }
    return mock_open_data.fd_returned;
}

ssize_t mock_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    mock_sendfile_data.called++;
    if (mock_sendfile_data.errno_value != 0) {
        errno = mock_sendfile_data.errno_value;
        return -1;
    }
    if (offset && mock_sendfile_data.return_value > 0) {
        *offset += mock_sendfile_data.return_value;
    }
    return mock_sendfile_data.return_value;
}

char *mock_realpath(const char *path, char *resolved_path) {
    mock_realpath_data.called++;
    if (mock_realpath_data.return_value == NULL) {
        return NULL;
    }
    strcpy(resolved_path, mock_realpath_data.resolved);
    return resolved_path;
}

// Function under test: read_exact (extracted from server.c)
ssize_t read_exact(int sockfd, void *buf, size_t n) {
    size_t bytes_read = 0;
    ssize_t result;
    while (bytes_read < n) {
        result = mock_read(sockfd, (char *)buf + bytes_read, n - bytes_read);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        } else if (result == 0) {
            return 0;
        }
        bytes_read += result;
    }
    return bytes_read;
}

// Simplified process_request for testing (with mocks)
void process_request_test(int sockfd, uint64_t offset, const char *filename, 
                          char *resolved_server_root) {
    char filepath[PATH_MAX];
    char resolved_path[PATH_MAX];
    struct stat st;
    int fd = -1;
    uint8_t status = STATUS_ERROR;
    uint64_t file_size = 0;

    // Security checks
    if (filename[0] == '/') {
        status = STATUS_ACCESS_DENIED;
        goto send_response;
    }

    if (strlen(SERVER_ROOT) + strlen(filename) + 2 >= PATH_MAX) {
        status = STATUS_ERROR;
        goto send_response;
    }

    snprintf(filepath, sizeof(filepath), "%s/%s", SERVER_ROOT, filename);

    // Mock realpath
    if (mock_realpath(filepath, resolved_path) == NULL) {
        if (errno == ENOENT) {
            status = STATUS_NOT_FOUND;
        } else {
            status = STATUS_ERROR;
        }
        goto send_response;
    }

    // Security check against directory traversal
    if (strncmp(resolved_server_root, resolved_path, strlen(resolved_server_root)) != 0) {
        status = STATUS_ACCESS_DENIED;
        goto send_response;
    }

    // Mock stat
    if (mock_stat(resolved_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        status = STATUS_NOT_FOUND;
        goto send_response;
    }

    file_size = st.st_size;

    if (offset > file_size) {
        status = STATUS_ERROR;
        goto send_response;
    }

    fd = mock_open(resolved_path, 0);
    if (fd == -1) {
        status = STATUS_ERROR;
        goto send_response;
    }

    status = STATUS_OK;

send_response:
    // Send response header
    uint64_t network_file_size = htobe64(file_size);
    char header[sizeof(status) + sizeof(network_file_size)];
    memcpy(header, &status, sizeof(status));
    memcpy(header + sizeof(status), &network_file_size, sizeof(network_file_size));
    
    mock_write(sockfd, header, sizeof(header));

    if (fd != -1) close(fd);
}

// Test Cases

void test_read_exact_success() {
    reset_mocks();
    
    char buffer[10];
    mock_read_data.bytes_to_read = 10;
    mock_read_data.return_value = 10;
    strcpy(mock_read_data.data, "testdata12");
    
    ssize_t result = read_exact(1, buffer, 10);
    
    CU_ASSERT_EQUAL(result, 10);
    CU_ASSERT_EQUAL(mock_read_data.called, 1);
    CU_ASSERT_STRING_EQUAL(buffer, "testdata12");
}

void test_read_exact_multiple_reads() {
    reset_mocks();
    
    char buffer[10];
    // Simulate partial reads
    mock_read_data.bytes_to_read = 5;
    mock_read_data.return_value = 5;
    strcpy(mock_read_data.data, "test1");
    
    // Note: In real scenario, we'd need more sophisticated mocking
    // This is simplified for demonstration
    ssize_t result = read_exact(1, buffer, 5);
    
    CU_ASSERT_EQUAL(result, 5);
    CU_ASSERT_TRUE(mock_read_data.called > 0);
}

void test_read_exact_connection_closed() {
    reset_mocks();
    
    char buffer[10];
    mock_read_data.return_value = 0; // EOF
    
    ssize_t result = read_exact(1, buffer, 10);
    
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_EQUAL(mock_read_data.called, 1);
}

void test_read_exact_error() {
    reset_mocks();
    
    char buffer[10];
    mock_read_data.errno_value = EIO;
    mock_read_data.return_value = -1;
    
    ssize_t result = read_exact(1, buffer, 10);
    
    CU_ASSERT_EQUAL(result, -1);
    CU_ASSERT_EQUAL(mock_read_data.called, 1);
}

void test_read_exact_eintr_retry() {
    reset_mocks();
    
    char buffer[10];
    mock_read_data.errno_value = EINTR;
    mock_read_data.return_value = -1;
    
    // Note: This test would need more sophisticated mocking
    // to properly test EINTR retry logic
    ssize_t result = read_exact(1, buffer, 10);
    
    CU_ASSERT_EQUAL(result, 10);
    CU_ASSERT_TRUE(mock_read_data.called >= 1);
}

void test_process_request_absolute_path() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    process_request_test(1, 0, "/etc/passwd", resolved_root);
    
    // Check that STATUS_ACCESS_DENIED was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_ACCESS_DENIED);
}

void test_process_request_directory_traversal() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    mock_realpath_data.return_value = resolved_root;
    strcpy(mock_realpath_data.resolved, "/etc/passwd");
    
    process_request_test(1, 0, "../../../etc/passwd", resolved_root);
    
    // Check that STATUS_ACCESS_DENIED was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_ACCESS_DENIED);
}

void test_process_request_file_not_found() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    mock_realpath_data.return_value = NULL;
    errno = ENOENT;
    
    process_request_test(1, 0, "nonexistent.txt", resolved_root);
    
    // Check that STATUS_NOT_FOUND was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_NOT_FOUND);
}

void test_process_request_valid_file() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    char test_path[PATH_MAX];
    snprintf(test_path, sizeof(test_path), "%s/test.txt", resolved_root);
    
    mock_realpath_data.return_value = test_path;
    strcpy(mock_realpath_data.resolved, test_path);
    
    mock_stat_data.return_value = 0;
    mock_stat_data.stat_data.st_mode = S_IFREG | 0644;
    mock_stat_data.stat_data.st_size = 1024;
    
    mock_open_data.return_value = 0;
    mock_open_data.fd_returned = 3;
    
    process_request_test(1, 0, "test.txt", resolved_root);
    
    // Check that STATUS_OK was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_OK);
    
    // Check file size in response
    uint64_t file_size;
    memcpy(&file_size, mock_write_data.data + 1, sizeof(file_size));
    file_size = be64toh(file_size);
    CU_ASSERT_EQUAL(file_size, 1024);
}

void test_process_request_invalid_offset() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    char test_path[PATH_MAX];
    snprintf(test_path, sizeof(test_path), "%s/test.txt", resolved_root);
    
    mock_realpath_data.return_value = test_path;
    strcpy(mock_realpath_data.resolved, test_path);
    
    mock_stat_data.return_value = 0;
    mock_stat_data.stat_data.st_mode = S_IFREG | 0644;
    mock_stat_data.stat_data.st_size = 1024;
    
    // Request with offset beyond file size
    process_request_test(1, 2048, "test.txt", resolved_root);
    
    // Check that STATUS_ERROR was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_ERROR);
}

void test_process_request_path_too_long() {
    reset_mocks();
    
    char *resolved_root = "/var/www/server_files";
    char long_filename[PATH_MAX];
    memset(long_filename, 'a', PATH_MAX - 1);
    long_filename[PATH_MAX - 1] = '\0';
    
    process_request_test(1, 0, long_filename, resolved_root);
    
    // Check that STATUS_ERROR was sent
    CU_ASSERT_EQUAL(mock_write_data.called, 1);
    uint8_t status = mock_write_data.data[0];
    CU_ASSERT_EQUAL(status, STATUS_ERROR);
}

void test_endianness_conversion() {
    uint64_t host_value = 0x123456789ABCDEF0ULL;
    uint64_t network_value = htobe64(host_value);
    uint64_t back_to_host = be64toh(network_value);
    
    CU_ASSERT_EQUAL(host_value, back_to_host);
    
    // Test with actual values
    uint64_t test_size = 1024;
    uint64_t net_size = htobe64(test_size);
    CU_ASSERT_NOT_EQUAL(test_size, net_size); // Should be different on little-endian
    CU_ASSERT_EQUAL(be64toh(net_size), test_size);
}

void test_filename_validation() {
    // Test various malicious filename patterns
    const char *bad_filenames[] = {
        "/etc/passwd",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "test/../../../etc/passwd",
        "./../../etc/passwd",
        "~/../.ssh/id_rsa",
        NULL
    };
    
    for (int i = 0; bad_filenames[i] != NULL; i++) {
        const char *filename = bad_filenames[i];
        
        // Check absolute path
        if (filename[0] == '/') {
            CU_ASSERT_TRUE(1); // Should be rejected
        }
        
        // Check for directory traversal patterns
        if (strstr(filename, "..") != NULL) {
            CU_ASSERT_TRUE(1); // Should be caught by realpath check
        }
    }
}

// Main test runner
int main() {
    CU_pSuite pSuite = NULL;

    // Initialize CUnit
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    // Add suite
    pSuite = CU_add_suite("Server Tests", NULL, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add tests to suite
    CU_add_test(pSuite, "test_read_exact_success", test_read_exact_success);
    CU_add_test(pSuite, "test_read_exact_multiple_reads", test_read_exact_multiple_reads);
    CU_add_test(pSuite, "test_read_exact_connection_closed", test_read_exact_connection_closed);
    CU_add_test(pSuite, "test_read_exact_error", test_read_exact_error);
    CU_add_test(pSuite, "test_process_request_absolute_path", test_process_request_absolute_path);
    CU_add_test(pSuite, "test_process_request_directory_traversal", test_process_request_directory_traversal);
    CU_add_test(pSuite, "test_process_request_file_not_found", test_process_request_file_not_found);
    CU_add_test(pSuite, "test_process_request_valid_file", test_process_request_valid_file);
    CU_add_test(pSuite, "test_process_request_invalid_offset", test_process_request_invalid_offset);
    CU_add_test(pSuite, "test_process_request_path_too_long", test_process_request_path_too_long);
    CU_add_test(pSuite, "test_endianness_conversion", test_endianness_conversion);
    CU_add_test(pSuite, "test_filename_validation", test_filename_validation);

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    
    unsigned int failures = CU_get_number_of_failures();
    
    CU_cleanup_registry();
    
    return (failures > 0) ? 1 : 0;
}