#ifndef NATIVE_TEST_H
#define NATIVE_TEST_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

// Test result structure
typedef struct {
    bool success;
    int error_code;
    char message[256];
    long duration_ms;
} native_test_result_t;

// Test configuration
typedef struct {
    const char* host;
    int port;
    const char* username;
    const char* password;
    int timeout_ms;
    int packet_count;
    int packet_size;
    int duration_seconds;
} native_test_config_t;

// Test functions
native_test_result_t test_tcp_connection(const native_test_config_t* config);
native_test_result_t test_tls_handshake(const native_test_config_t* config);
native_test_result_t test_softether_handshake(const native_test_config_t* config);
native_test_result_t test_authentication(const native_test_config_t* config);
native_test_result_t test_session(const native_test_config_t* config);
native_test_result_t test_data_transmission(const native_test_config_t* config);
native_test_result_t test_keepalive(const native_test_config_t* config);
native_test_result_t test_full_lifecycle(const native_test_config_t* config);

// Utility functions
void test_result_init(native_test_result_t* result, bool success, int error_code, 
                      const char* message, long duration_ms);
long get_test_timestamp_ms(void);
const char* test_error_to_string(int error_code);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_TEST_H
