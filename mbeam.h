#ifndef MBEAM_H_
#define MBEAM_H_

#define PORT                8080        // Server port to connect to
#define BUFFER_SIZE         8192        // File contents in working memory
#define SERVER_ROOT         "./server_files"
#define MAX_FILENAME_LEN    1024        // Max filename length without the path

// Protocol status messages
#define STATUS_OK           0           // All good
#define STATUS_NOT_FOUND    1           // File not found on server
#define STATUS_ERROR        2           // Server error happened
#define STATUS_ACCESS_DENIED 3          // No access to file or permission denied

#endif //MBEAM_H_