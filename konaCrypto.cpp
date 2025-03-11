/*
#include <sys/_types.h>
#include "aes_alt.h"
#include <sys/_intsup.h>
#include <string.h>
*/
#include "konaCrypto.h"
#include "mbedtls/aes.h"
#include <string.h>
#include "appGlobals.h"

unsigned char aes_key[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

unsigned char apdu_command[] = {0x00, 0xA4, 0x04, 0x00, 0x01, 0xA0};

// Add PKCS#7 Padding
size_t add_pkcs7_padding(unsigned char *buffer, size_t data_len, size_t buffer_size){
  size_t padding_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
  if(data_len + padding_len > buffer_size){
    return 0;
  }
  
  for(size_t i = 0; i < padding_len; i++){
    buffer[data_len + i] = (unsigned char)padding_len;
  }
  return data_len + padding_len;
}

// Remove PKCS#7 Padding
size_t remove_pkcs7_padding(unsigned char *buffer, size_t data_len){
  if(data_len == 0){
    return 0;
  }

  size_t padding_len = buffer[data_len - 1];
  if(padding_len > AES_BLOCK_SIZE || padding_len > data_len){
    return 0;
  }
  return data_len - padding_len;
}

// AES Crypto
//
// cryptoMode : MBEDTLS_AES_ENCRYPT / MBEDTLS_AES_DECRYOPT
//
size_t aes_cryptoData(unsigned char *input, size_t input_len, unsigned char *output, int cryptoMode){
  mbedtls_aes_context aes;
  unsigned char iv[AES_BLOCK_SIZE] = {0};

  mbedtls_aes_init(&aes);
  if(cryptoMode == MBEDTLS_AES_ENCRYPT){
    mbedtls_aes_setkey_enc(&aes, aes_key, AES_KEY_SIZE);
  }
  else if(cryptoMode == MBEDTLS_AES_DECRYPT){
    mbedtls_aes_setkey_dec(&aes, aes_key, AES_KEY_SIZE);
  }
  else{
    return 0;
  }

  size_t processed_len = input_len;

  if(cryptoMode == MBEDTLS_AES_ENCRYPT){
    processed_len = add_pkcs7_padding(input, input_len, input_len + AES_BLOCK_SIZE);
  }

  mbedtls_aes_crypt_cbc(&aes, cryptoMode, processed_len, iv, input, output);

  mbedtls_aes_free(&aes);

  if(cryptoMode == MBEDTLS_AES_DECRYPT){
    processed_len = remove_pkcs7_padding(output, processed_len);
  }

  return processed_len;
}

void send_apdu_to_sim(const unsigned char *data, size_t data_len){
  size_t offset = 0;
  int chunk_size;
  char at_command[AT_CMD_BUFFER_SIZE];

  while(offset < data_len){
    chunk_size = (data_len - offset > APDU_MAX_DATA) ? APDU_MAX_DATA : (data_len - offset);

    char *ptr = at_command;

    // AT+CSIM=<Length>
    ptr += sprintf(ptr, "AT+CSIM=%d,\"", chunk_size + APDU_HEADER_SIZE);
    
    // APDU Header
    ptr += sprintf(ptr, "00D6%02X%02X%02X", (offset >> 8) & 0xFF, offset & 0xFF, chunk_size);

    // APDU Data
    for(int i = 0; i < chunk_size; i++){
      ptr += sprintf(ptr, "%02X", data[offset + i]);
    }

    strcat(at_command, "\"");

    // send UART
    //uart_send(at_command);

    offset += chunk_size;
  }
}

void aesTest()
{
  // AES Test
  unsigned char input[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
  unsigned char output[128];
  aes_cryptoData(input, sizeof(input), output, MBEDTLS_AES_ENCRYPT);
  
  // 암호화된 데이터를 16진수 문자열로 변환하여 출력
  char hex_output[33];  // 16바이트 * 2 + 널문자(\0)
  for (int i = 0; i < 16; i++) {
      sprintf(hex_output + i * 2, "%02X", output[i]);
  }
  hex_output[32] = '\0';  // 문자열 끝 처리
  LOG_INF("Encrypted HEX %s", hex_output); 
}
