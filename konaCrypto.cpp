/*
#include <sys/_types.h>
#include "aes_alt.h"
#include <sys/_intsup.h>
#include <string.h>
*/
//#include "mbedtls/aes.h"
#include "konaCrypto.h"
#include <string.h>
#include "appGlobals.h"

unsigned char aes_key[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

unsigned char aes_key_256[32] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

unsigned char apdu_command[] = {0x00, 0xA4, 0x04, 0x00, 0x01, 0xA0};

unsigned char finalInput[20000];



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
// keySize : AES_KEY_SIZE_128 / AES_KEY_SIZE_256
//
size_t aes_cryptoData(unsigned char *input, size_t input_len, unsigned char *output, int cryptoMode, int keySize){
  mbedtls_aes_context aes;
  unsigned char iv[AES_BLOCK_SIZE] = {0};
  
  memcpy(finalInput, input, input_len);

  mbedtls_aes_init(&aes);
  if(keySize == AES_KEY_SIZE_128){
    if(cryptoMode == MBEDTLS_AES_ENCRYPT){
      mbedtls_aes_setkey_enc(&aes, aes_key, keySize);
    }
    else if(cryptoMode == MBEDTLS_AES_DECRYPT){
      mbedtls_aes_setkey_dec(&aes, aes_key, keySize);
    }
  }
  else if(keySize == AES_KEY_SIZE_256){
    if(cryptoMode == MBEDTLS_AES_ENCRYPT){
      mbedtls_aes_setkey_enc(&aes, aes_key_256, keySize);
    }
    else if(cryptoMode == MBEDTLS_AES_DECRYPT){
      mbedtls_aes_setkey_dec(&aes, aes_key_256, keySize);
    }
  }
  
  else{
    return 0;
  }

  size_t processed_len = input_len;

  if(cryptoMode == MBEDTLS_AES_ENCRYPT){
    processed_len = add_pkcs7_padding(finalInput, input_len, input_len + AES_BLOCK_SIZE);
  }

  mbedtls_aes_crypt_cbc(&aes, cryptoMode, processed_len, iv, finalInput, output);

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
  unsigned char output[128] = {};
  unsigned char decOutput[128] = {};
  int64_t start_time = esp_timer_get_time();
  size_t encLen = aes_cryptoData(input, sizeof(input), output, MBEDTLS_AES_ENCRYPT, AES_KEY_SIZE_256);
  int64_t end_time = esp_timer_get_time();
  //ESP_LOGI(TAG, "%ums", (uint32_t)((fr_end - fr_start) / 1000));
  LOG_INF("Encrypt time : %u us", (uint32_t)((end_time - start_time)));

  char printData[128] = {};
  //convertHexString(input, sizeof(input), printData);
  //LOG_INF("Plain Hex : %s", printData);
  convertHexStringAndPrint(input, sizeof(input), "Plain Hex");
  //convertHexString(aes_key, 16, printData);
  //LOG_INF("Key Hex : %s", printData);
  convertHexStringAndPrint(aes_key, 16, "Key Hex");
  //convertHexString(output, encLen, printData);
  //LOG_INF("Encrypt Hex : %s", printData);
  convertHexStringAndPrint(output, encLen, "Encrypt Hex");

  size_t decLen = aes_cryptoData(output, encLen, decOutput, MBEDTLS_AES_DECRYPT, AES_KEY_SIZE_256);
  convertHexString(output, encLen, printData);
  LOG_INF("Encrypt Hex : %s", printData);
  convertHexString(aes_key, 16, printData);
  LOG_INF("Key Hex : %s", printData);
  convertHexString(decOutput, decLen, printData);
  LOG_INF("Decrypt Hex : %s", printData);
}

size_t convertHexString(void *input, size_t input_len, char *output){
  uint8_t* data = (uint8_t*)input;
  size_t outlen = input_len * 2;
  char hex_output[outlen + 1];
  
  for(int i = 0; i < input_len; i++){
    sprintf(hex_output + i * 2, "%02X", data[i]);
  }
  hex_output[outlen] = '\0';
  memcpy(output, hex_output, outlen + 1);
  return outlen;
}

void convertHexStringAndPrint(void *input, size_t input_len, char* title) {
  size_t buffer_size = 128;
  if (!input || input_len == 0) return;

  if (title && strlen(title) > 0) {
    Serial.print(title);
    Serial.println(" : ");
  }

  uint8_t* data = (uint8_t*)input;
  size_t totalLen = input_len * 2;
  size_t pos = 0;

  while (pos < input_len) {
      size_t chunk_len = min(buffer_size / 2, input_len - pos);  // 바이트 수

      char hex_output[buffer_size + 1];  // 2자리 16진수 * chunk_len
      for (size_t i = 0; i < chunk_len; i++) {
          sprintf(hex_output + i * 2, "%02X", data[pos + i]);
      }
      hex_output[chunk_len * 2] = '\0';

      Serial.print(hex_output);
      Serial.flush();
      delay(5);  // 출력 안정화
      pos += chunk_len;
  }

  Serial.println();  // 줄바꿈
}

size_t getCryptoLen(){
  size_t getLength = 0;

  return getLength;
}


void startAWSTLSSet(){
  connect_to_aws_with_tls(&conn);
}


// 구현 검토 필요
/*
int se_get_bitlen(const void *ctx) {
    // SE 안의 키가 ECDSA P-256이면 → 256비트
    return 256;
}

int se_sign_func(void *ctx, mbedtls_md_type_t md_alg,
  const unsigned char *hash, size_t hash_len,
  unsigned char *sig, size_t *sig_len,
  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  // 1. hash → base64 encoding
  char base64_hash[128];
  size_t olen = 0;

  int ret = mbedtls_base64_encode(
      (unsigned char *)base64_hash, sizeof(base64_hash), &olen,
      hash, hash_len
  );

  if (ret != 0) {
      printf("Base64 encoding failed\n");
      return;
  }
  base64_hash[olen] = '\0';

  // 2. AT 명령으로 서명 요청 (APDU 포함)
  char apdu_cmd[256];
  snprintf(apdu_cmd, sizeof(apdu_cmd), "AT+APDU=00A40000023F01%s\r\n", base64_hash);
  send_at(apdu_cmd);  // UART 전송 함수

  // 3. 응답에서 서명 수신 (base64)
  char base64_sig[256];
  if (!read_response_until_ok(base64_sig)) {
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  }

  // 4. base64 decode → sig
  int ret = mbedtls_base64_decode(
    sig, sizeof(sig), &sig_len,
    (const unsigned char *)base64_sig, strlen(base64_sig)
  );

  if (ret != 0) {
      printf("Base64 디코딩 실패: -0x%04X\n", -ret);
  } else {
      printf("디코딩 성공, 서명 길이: %d\n", (int)sig_len);
  }

  return 0;
}

int se_can_do(mbedtls_pk_type_t type) {
  return type == MBEDTLS_PK_ECKEY;  // ECDSA만 지원한다고 가정
}

static mbedtls_pk_info_t se_pk_info = {
    MBEDTLS_PK_ECDSA,
    "SE_ECDSA",
    se_get_bitlen,
    se_can_do,
    se_sign_func,
    NULL, NULL, NULL, NULL, NULL, NULL
};

void connect_to_aws_with_se_cert(const char *cert_pem, const char *host) {
  mbedtls_net_context net;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cert;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_pk_context pk;

  const char *pers = "aws_tls";

  mbedtls_net_init(&net);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  mbedtls_pk_init(&pk);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
              (const unsigned char *)pers, strlen(pers));

  // 인증서 파싱
  mbedtls_x509_crt_parse(&cert, (const unsigned char *)cert_pem, strlen(cert_pem) + 1);

  // SE 개인키를 참조하는 pk_context 설정
  pk.private_pk_info = &se_pk_info;
  pk.private_pk_ctx = prvtkey_pem;  // 실제 서명 컨텍스트가 있다면 여기에 할당

  mbedtls_ssl_config_defaults(&conf,
                  MBEDTLS_SSL_IS_CLIENT,
                  MBEDTLS_SSL_TRANSPORT_STREAM,
                  MBEDTLS_SSL_PRESET_DEFAULT);

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, cert.next, NULL);  // AWS Root CA 체인 설정 필요
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_own_cert(&conf, &cert, &pk);

  mbedtls_ssl_setup(&ssl, &conf);
  mbedtls_ssl_set_hostname(&ssl, host);

  // TLS 연결 시도
  if (mbedtls_net_connect(&net, host, "443", MBEDTLS_NET_PROTO_TCP) != 0) {
    printf("TCP connection failed\n"); return;
  }
  mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

  int ret = mbedtls_ssl_handshake(&ssl);
  if (ret != 0) {
    char errbuf[128];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    printf("TLS handshake failed: %s\n", errbuf);
    return;
  }

  printf("[TLS] Handshake with AWS successful using SE signing!\n");
  mbedtls_ssl_close_notify(&ssl);
  mbedtls_net_free(&net);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_x509_crt_free(&cert);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}*/

//#define FILE_PATH "/spiffs/video.avi"
//#define PUT_PATH "/your-object-path?X-Amz-Algorithm=..."
#define HOST "https://did-iot.s3.ap-northeast-2.amazonaws.com"
#define PORT "443"

void connect_to_aws_with_tls(tls_connection_t *conn) {
  //mbedtls_net_context net;
  //mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cert;
  mbedtls_x509_crt ca_cert;
  mbedtls_pk_context pk;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  mbedtls_net_init(&conn->net);
  mbedtls_ssl_init(&conn->ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cert);
  mbedtls_x509_crt_init(&ca_cert);
  mbedtls_pk_init(&pk);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char *pers = "aws_tls";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)pers, strlen(pers));

  String cert_str = readFile("/Device_certificate.pem.crt");
  String ca_str   = readFile("/AmazonRootCA3.pem");
  String key_str  = readFile("/Device_private.pem.key");

  mbedtls_x509_crt_parse(&cert, (const unsigned char *)cert_str.c_str(), cert_str.length() + 1);
  mbedtls_x509_crt_parse(&ca_cert, (const unsigned char *)ca_str.c_str(), ca_str.length() + 1);
  mbedtls_pk_parse_key(&pk, (const unsigned char *)key_str.c_str(), key_str.length() + 1, NULL, 0, NULL, NULL);

  LOG_INF("");

  mbedtls_ssl_config_defaults(&conf,
                              MBEDTLS_SSL_IS_CLIENT,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &ca_cert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_own_cert(&conf, &cert, &pk);

  mbedtls_ssl_setup(&conn->ssl, &conf);
  mbedtls_ssl_set_hostname(&conn->ssl, HOST);

  configTime(9 * 3600, 0, "pool.ntp.org");
  delay(5000);  // 시간 잡힐 때까지 대기
  
  if (mbedtls_net_connect(&conn->net, HOST, PORT, MBEDTLS_NET_PROTO_TCP) != 0) {
    LOG_INF("[Error] TCP 연결 실패\n"); return;
  }
  mbedtls_ssl_set_bio(&conn->ssl, &conn->net, mbedtls_net_send, mbedtls_net_recv, NULL);

  time_t now = time(NULL);
  LOG_ERR("ctime : %s", ctime(&now)); 
    
  int ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret != 0) {
    LOG_INF("[Error] TLS 핸드셰이크 실패\n");
    char errbuf[128];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    LOG_ERR("TLS handshake failed: -0x%04X: %s\n", -ret, errbuf);
    return;
  }

  LOG_INF("[Info] TLS 연결 성공 - AWS S3 전송 시작\n");
/*
  FILE *fp = fopen(FILE_PATH, "rb");
  if (!fp) {
    LOG_INF("[Error] 파일 열기 실패\n"); return;
  }
  fseek(fp, 0, SEEK_END);
  size_t file_size = ftell(fp);
  rewind(fp);

  char header[512];
  snprintf(header, sizeof(header),
           "PUT %s HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Content-Length: %d\r\n"
           "Content-Type: video/avi\r\n\r\n",
           PUT_PATH, HOST, (int)file_size);
  mbedtls_ssl_write(&ssl, (const unsigned char *)header, strlen(header));

  unsigned char buf[1024];
  size_t len;
  while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
      mbedtls_ssl_write(&ssl, buf, len);
  }
  fclose(fp);

  unsigned char response[512];
  int resp_len = mbedtls_ssl_read(&ssl, response, sizeof(response) - 1);
  if (resp_len > 0) {
      response[resp_len] = 0;
      LOG_INF("[Response] %s\n", response);
  }
*/

/*
  mbedtls_ssl_close_notify(&conn->ssl);
  mbedtls_net_free(&conn->net);
  mbedtls_ssl_free(&conn->ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_x509_crt_free(&cert);
  mbedtls_x509_crt_free(&ca_cert);
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
*/
}

bool read_response_until_ok(char *out_buf, size_t out_buf_size) {
  size_t idx = 0;
  unsigned long start_time = millis();
  bool ok_received = false;

  while (millis() - start_time < 3000) {  // 3초 타임아웃
      if (Serial.available()) {
          char c = Serial.read();
          if (idx < out_buf_size - 1) {
              out_buf[idx++] = c;
          }

          out_buf[idx] = '\0';
          if (strstr(out_buf, "OK") != NULL) {
              ok_received = true;
              break;
          }
      }
  }

  // Base64 부분만 잘라낼 수도 있음 (간단한 처리)
  if (ok_received) {
      char *start = strchr(out_buf, ':');
      if (start) {
          start++;  // ':' 다음부터
          while (*start == ' ') start++;
          memmove(out_buf, start, strlen(start) + 1);
      }
  }

  return ok_received;
}
