# High-Performance MultiBeam Concurrent File Server by FSK

A robust, secure, and high-performance TCP file server implemented in C for Linux.

## Features

*   **Concurrent Connections:** Multi-threaded architecture (`pthreads`).
*   **Performance Optimization:** Utilizes Linux `sendfile()` for zero-copy file transfers.
*   **Large File Support & Resumption:** Supports 64-bit file sizes and resumable downloads.
*   **Security:** Robust protection against directory traversal attacks using `realpath()`.
*   **Robustness:** Uses a binary protocol, handles endianness correctly, and integrates with `syslog`.

### Binary Protocol
    Client initiates the connection to server:
    Client -> Server
        2 Bytes: filepath/name length x Bytes
        x Bytes: filepath/name
        8 Bytes: offset (to resume partial transfers)

    Server responds with following:
    Server -> Client
        1 Bytes: Status code
        8 Bytes: file size = y Bytes
        y Bytes: file data

## Build Instructions
Requires GCC and Make. Run make command to build binaries for client and server.

Requires CUnit for unit testing.
Valgrind for memcheck memory leak testing.
gcov for code coverage reporting.

```bash
make all
# Ubuntu/Debian
make -f Makefile.test install-cunit
# Compile and run unit tests
make -f Makefile.test tests
make -f Makefile.test test
```

## Usage

### Server
The server serves files from the ./server_files directory (defined by SERVER_ROOT) on port 8080 (defined by PORT). Run the server using following command in one terminal

```bash
./mbeam_file_server
```

### Server Logs
Monitor logs in another terminal. Adjust path if necessary (e.g., /var/log/messages)

```bash
tail -f /var/log/syslog | grep mbeam_file_server
```

### Client
Run client in another terminal to connect to server using <server_ip> requesting for file on server <remote_filename> and copy it over into local file <local_output_filename>
```bash
./mbeam_client <server_ip> <remote_filename> <local_output_filename>
```
Example:
```bash
./mbeam_client 127.0.0.1 hello.txt download_hello.txt
```
NOTE: To run the above command first follow the steps to "Setup the Test Environment" below.

## Setup the Test Environment
 Create the server files directory and test files in the directory where the server code is located.

 ```bash
mkdir -p server_files
# Create a small text file
echo "Hello MultiBeam TCP World" > server_files/hello.txt
# Create a large binary file (e.g., 100MB)
dd if=/dev/urandom of=server_files/largefile.bin bs=1M count=100
```

## Manual Testing
### 1. Download small text file
Use the command
```bash
./mbeam_client 127.0.0.1 hello.txt download_hello.txt
```

### 2. Download large file with progress bar
Use the following command to download a large file and observe progress bar.
```bash
./mbeam_client 127.0.0.1 largefile.bin download_large.bin
```

### 3. Download multiple large file to test concurrency / multi-threading
Run multiple clients  in different terminals using following command
```bash
./mbeam_client 127.0.0.1 largefile.bin download_large.bin
```

### 4. Test Resumable Downloads
Start the large file download again.
Interrupt the client (Ctrl+C) midway.
Resume by runing the same command again.
```bash
./mbeam_client 127.0.0.1 largefile.bin download_large.bin.
```
NOTE: The client will detect the partial file and resume from the interruption point.

## Unit Tests

### Key Features of the Tests
* **Mock/Stub Functions:** All system calls (read, write, socket, connect, stat, open, sendfile, realpath) are mocked to isolate the logic being tested.
* **Comprehensive Coverage:** Tests cover normal operations, error conditions, edge cases, and security vulnerabilities.
* **Protocol Validation:** Tests verify correct byte order conversions and protocol message formatting.
* **Security Testing:** Includes tests for directory traversal attacks, absolute paths, and other security concerns.
* **Resume Capability:** Tests verify that the client correctly handles partial downloads and resumption.

### Server Unit Tests
Tests the following functionality:
* **read_exact function:** Success, partial reads, connection closed, errors, EINTR retry
* **Security features:** Absolute path rejection, Directory traversal prevention, Path validation
* **File handling:** Valid file requests, File not found scenarios, Invalid offset handling, Path length limits
* **Protocol implementation:** Endianness conversions, Response header formatting
* **Filename validation:** Various malicious patterns

### Client Unit Tests
Tests the following functionality:
* **read_exact function:** Success, partial reads
* **Protocol formatting:** Request structure validation
* **Resume capability:** Partial download continuation
* **Status handling:** All server status codes (OK, NOT_FOUND, ACCESS_DENIED, ERROR)
* **Connection management:** Socket creation failures, Connection failures, Invalid IP addresses, Premature disconnections
* **File operations:** Already complete files, Buffer size handling
* **Endianness operations:** 16-bit and 64-bit conversions

### Commands to run Unit Tests
Provides make targets for:

* ```make tests```: Build all test executables
* ```make test```: Run all tests
* ```make test-server```: Run server tests only
* ```make test-client```: Run client tests only
* ```make memcheck```: Run Valgrind memory checks
* ```make coverage```: Generate code coverage reports
* ```make install-cunit:``` Helper to install CUnit on various platforms

### Usage of Tests
1. Install CUnit:
```bash
# Ubuntu/Debian
make -f Makefile.test install-cunit

# RHEL/CentOS/Fedora
make -f Makefile.test install-cunit-rhel

# macOS
make -f Makefile.test install-cunit-mac
```

2. Compile the tests:
```bash
make -f Makefile.test tests
```

3. Run all tests:
```bash
make -f Makefile.test test
```

4. Check for memory leaks:
```bash
make -f Makefile.test memcheck
```

5. Generate coverage reports:
```bash
make -f Makefile.test coverage
```
The tests use a modular approach with reset_mocks() called before each test to ensure test isolation. The mock data structures allow you to configure specific behaviors for each test case, making it easy to test both success and failure scenarios.

## Limitations & Improvements
### Limitations

*   **Refactoring of Code:** Keep only main() and thread functions in server.c and move all functions into separate server_libs.c and common_libs.c so they can be tested with unit tests. Similar refactoring for client.c into client_libs.c.
*   **Scalability (C10K Problem):** While the thread-per-connection model combined with `sendfile()` is very efficient, an event-driven architecture (using `epoll` or `io_uring`) is superior for handling tens of thousands of simultaneous connections, as it avoids the overhead of managing a large number of threads.
*   **Security (Encryption/Authentication):** Data is transferred in plaintext over TCP. There is no mechanism for authenticating clients or encrypting the data stream.
*   **Configuration Management:** Settings are hardcoded rather than dynamically loaded from a configuration file.

### Potential Improvements

*   **TLS/SSL Integration:** Integrate OpenSSL to provide encrypted communication, which is essential for production environments.
*   **Event-Driven Architecture:** Refactor the networking layer to use `epoll` (or `io_uring`) for massive scalability.
*   **Thread Pooling:** As an alternative to `epoll`, implementing a thread pool would reduce the overhead of thread creation/destruction under high connection rates.
*   **Configuration File:** Load settings (port, root directory, connection limits, log levels) from a configuration file.
*   **Rate Limiting:** Implement bandwidth throttling to prevent single clients from saturating the network connection.
