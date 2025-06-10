#pragma once
#include <stddef.h>
#include <stdio.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#define APDU_MAX_SIZE 255
#define APDU_HEADER_SIZE 5
#define APDU_MAX_DATA (APDU_MAX_SIZE - APDU_HEADER_SIZE)
#define AT_CMD_BUFFER_SIZE (APDU_MAX_SIZE * 2 + 20)
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE_128 128
#define AES_KEY_SIZE_256 256

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
  } tls_connection_t;
static tls_connection_t conn;

size_t aes_cryptoData(unsigned char *input, size_t input_len, unsigned char *output, int cryptoMode, int keySize);
//size_t convertHexString(unsigned char *input, size_t input_len, char *output);
size_t convertHexString(void *input, size_t input_len, char *output);
//void convertHexStringAndPrint(void *input, size_t input_len);
void convertHexStringAndPrint(void *input, size_t input_len, char* title = "");
size_t add_pkcs7_padding(unsigned char *buffer, size_t data_len, size_t buffer_size);
void aesTest();
void startAWSTLSSet();
void connect_to_aws_with_tls(tls_connection_t *conn);