#pragma once
#include <stddef.h>
#include <stdio.h>

#define APDU_MAX_SIZE 255
#define APDU_HEADER_SIZE 5
#define APDU_MAX_DATA (APDU_MAX_SIZE - APDU_HEADER_SIZE)
#define AT_CMD_BUFFER_SIZE (APDU_MAX_SIZE * 2 + 20)
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 128

size_t aes_cryptoData(unsigned char *input, size_t input_len, unsigned char *output, int cryptoMode);
void aesTest();