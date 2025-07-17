//#include "libLcd.h"
#include "libduali.h"
#include "global.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// KSS SDK header
#include "kss_def.h"
#include "kona_kss_api.h"
#include "kose_tlv.h"
#include "scp03_Types.h"
#include "aws_iot_mbedtls_mqtt.h"

#define MI_OK 			0x00
#define MAX_APDU_LEN 	256

// 헥스 문자열을 unsigned char 배열로 변환하는 함수
int hex_string_to_bytes(const char *hex_str, unsigned char *byte_array, size_t apdu_str_len) {
    if (hex_str == NULL || byte_array == NULL) {
        fprintf(stderr, "Error: Null pointer passed to hex_string_to_bytes.\n");
        return -1;
    }

    if (apdu_str_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be an even number. Length: %zu\n", apdu_str_len);
        return -1; // 헥스 문자열은 항상 짝수 길이여야 합니다 (바이트 당 2개의 헥스 문자)
    }

    size_t i;
    for (i = 0; i < apdu_str_len / 2; i++) {
        char hex_byte_str[3]; // 두 개의 헥스 문자와 널 종단 문자('\0')
        hex_byte_str[0] = hex_str[i * 2];
        hex_byte_str[1] = hex_str[i * 2 + 1];
        hex_byte_str[2] = '\0';

        // strtol 함수를 사용하여 16진수 문자열을 long 정수로 변환
        byte_array[i] = (unsigned char)strtol(hex_byte_str, NULL, 16);
    }
    return (int)(apdu_str_len / 2); // 변환된 바이트 수 반환
}

static int Test_SAM(unsigned char *send_apdu, int len)
{
	int j=0;
	uint8_t sam_err_count = 0;
	uint8_t trxbuf[30], i=0;
	trxbuf[0] = 0x00;
	if(DE_SAM_on(0,5,&len,trxbuf)==MI_OK){
		{
			if(DE_SAM_apdu(i,5,send_apdu,&len,trxbuf)==MI_OK) {
				if(DE_SAM_off(0)!=MI_OK){
					printf("\n\rSAM%d POWER_OFF1 Error", i);
					sam_err_count++;
				}
				else
				{
					printf("\n\rret (%d) : ", len);
					for(j=0;j<len;j++)
					{
						printf("%02X ", trxbuf[j]);
					}
					printf("\n\r");
				}	
			}
			else{
				printf("\n\rSAM%d APDU Error", i);
				sam_err_count++;
				if(DE_SAM_off(0)!=MI_OK){
					printf("\n\rSAM%d POWER_OFF2 Error", i);
					sam_err_count++;
				}	
			}
		}
	}
	else{
		printf("\n\rSAM%d POWER_ON Error", i);
		sam_err_count++;
	}

	//printf("\n\rSAM Error cnt %d\n\r", sam_err_count);

	return sam_err_count;
}

static smStatus_t cross_DE_SAM_apdu(struct KoseSession * pSession, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen){
    int32_t slotno = 0;
    int32_t out_len = 0;
    smStatus_t retStatus = SM_NOT_OK;

    if (cmdBufLen > INT32_MAX) {
        return retStatus;
    } else {
        if(DE_SAM_apdu(slotno, cmdBufLen, cmdBuf, &out_len, rsp) ==  MI_OK){
            *rspLen = (size_t)out_len;
            retStatus = (rsp[out_len - 2] << 8) | rsp[out_len - 1];
            if ((rsp[out_len - 2] == 0x61)) {
                uint8_t le = rsp[out_len - 1];
                uint8_t get_resp_apdu[5] = {0x00, 0xC0, 0x00, 0x00, le};
                uint8_t temp_rsp[258] = {0};
                size_t temp_rsp_len = 0;

                if (DE_SAM_apdu(slotno, sizeof(get_resp_apdu), get_resp_apdu, &out_len, temp_rsp) == MI_OK) {
                    size_t main_data_len = out_len - 2;
                    if ((*rspLen) + main_data_len < *rspLen) {
                        return SM_NOT_OK;
                    }
                    memcpy(rsp + (*rspLen - 2), temp_rsp, main_data_len + 2);
                    *rspLen = (*rspLen - 2) + main_data_len + 2;
                    retStatus = (temp_rsp[out_len - 2] << 8) | temp_rsp[out_len - 1];
                }
            }
            else if ((rsp[out_len - 2] == 0x6C)) {
				uint8_t sndbuf2[5];
				memcpy(sndbuf2, cmdBuf, 5);
				sndbuf2[4] = rsp[out_len - 2];
				if (DE_SAM_apdu(slotno, cmdBufLen, sndbuf2, &out_len, rsp) == MI_OK) {
                }
			}
            return retStatus;
        }
    }

    return retStatus;
}

int main(int argc, char *argv[]) {
    unsigned char apdu_buffer[MAX_APDU_LEN];
    memset(apdu_buffer, 0, sizeof(apdu_buffer));

    const char *sdk_str; // SDK 명령 시작 지정 문자열
    const char *sdk_com_str; // SDK API 문자열
            
    if (argc != 2) {
        if (argc == 3) {
            sdk_str = argv[1]; // SDK 명령 시작 지정 문자열
            sdk_com_str = argv[2]; // SDK API 문자열
            if(memcmp("KSS", sdk_str, 3) != 0){
                printf("Usage: %s KSS <KSS_SDK_COMMAND>\n", argv[0]);
                printf("Example: %s KSS kss_session_open\n", argv[0]);
                return 1; // 인자 개수가 올바르지 않으면 종료    
            }
        }
        else{
            printf("Usage: %s <APDU_HEX_STRING>\n", argv[0]);
            printf("Example: %s 00A4040007A0000000030000\n", argv[0]);
            return 1; // 인자 개수가 올바르지 않으면 종료
        }
    }

    ///////////////////////////// KSS SDK Test ////////////////////////////////////
    if (argc == 3) {
        kss_status_t kStatus = kStatus_KSS_Fail;

        uint8_t trxbuf[30];
        int len;
	    trxbuf[0] = 0x00;

        if(memcmp(KSS_SESSION_OPEN, sdk_com_str, (sizeof(KSS_SESSION_OPEN) - 1)) == 0){
            printf(KSS_SESSION_OPEN "Start!!\n");
            int32_t res = 0;
            res = DE_SAM_init();
            
            if(DE_SAM_on(0,5,&len,trxbuf)==MI_OK){
                kss_session_t session;
                SE_Connect_Ctx_t se_conn_ctx;
                void *connectionData = NULL;
                
                se_conn_ctx.connType = kType_SE_Conn_Type_UART;
                se_conn_ctx.conn_ctx = &cross_DE_SAM_apdu;
                connectionData = &se_conn_ctx;
                kStatus = kss_session_open(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
                if (kStatus_KSS_Success != kStatus) {
                    printf(KSS_SESSION_OPEN "failed res : %u\n", kStatus);
                }
            }

            DE_SAM_off(0);
            printf(KSS_SESSION_OPEN "End!!\n");
        }
        else if(memcmp(KSS_MBEDTLS_TEST, sdk_com_str, (sizeof(KSS_MBEDTLS_TEST) - 1)) == 0){
            printf(KSS_MBEDTLS_TEST "Start!!\n");
            int32_t res = 0;
            res = DE_SAM_init();
            
            if(DE_SAM_on(0,5,&len,trxbuf)==MI_OK){
                // kss_session_open
                kss_session_t session;
                SE_Connect_Ctx_t se_conn_ctx;
                void *connectionData = NULL;
                
                se_conn_ctx.connType = kType_SE_Conn_Type_UART;
                se_conn_ctx.conn_ctx = &cross_DE_SAM_apdu;
                connectionData = &se_conn_ctx;
                kStatus = kss_session_open(&session, kType_KSS_SecureElement, 0, kKSS_ConnectionType_Plain, connectionData);
                if (kStatus_KSS_Success != kStatus) {
                    printf(KSS_SESSION_OPEN "failed res : %u\n", kStatus);
                }

                // aws iot mbedtls mqtt test
                aws_iot_mbedtls_mqtt_test(&session);
            }

            DE_SAM_off(0);
            printf(KSS_MBEDTLS_TEST "End!!\n");
        }
        return 1;
    }

    const char *hex_apdu_str = argv[1]; // 첫 번째 명령줄 인자가 APDU 헥스 문자열
    size_t hex_str_len = strlen(hex_apdu_str);

    // 헥스 문자열의 길이가 짝수인지 확인
    if (hex_str_len % 2 != 0) {
        fprintf(stderr, "err: APDU is Not an even number. (Len: %zu)\n", hex_str_len);
        return 1;
    }

    // 변환될 APDU 명령의 바이트 길이
    int apdu_command_len = hex_str_len / 2;

    // 버퍼 크기 초과 여부 확인
    if (apdu_command_len > MAX_APDU_LEN) {
        fprintf(stderr, "err: input APDU command exceeds maximum buffer size(%d). (input: %d)\n", MAX_APDU_LEN, apdu_command_len);
        return 1;
    }

    // 헥스 문자열을 바이트 배열로 변환
    int converted_len = hex_string_to_bytes(hex_apdu_str, apdu_buffer, hex_str_len);
    if (converted_len == -1 || converted_len != apdu_command_len) {
        fprintf(stderr, "err: conversion failed.\n");
        return 1;
    }

    printf("APDU (%d) : ", converted_len);
    for (int i = 0; i < converted_len; i++) {
        printf("%02X ", apdu_buffer[i]);
    }
    printf("\n\r");

	DE_SAM_init();

	Test_SAM(apdu_buffer, converted_len);

	DE_SAM_off(0);
	return 0;
}
