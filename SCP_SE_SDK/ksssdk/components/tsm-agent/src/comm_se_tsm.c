/*
 * comm_se_in_tsm.cpp
 *
 *  Created on: Apr 17, 2018
 *      Author: Autonu
 */

#include "http_requester.h"
#include "response_structs.h"
#include <cJSON.h>
#include "http_conf.h"
#include "enums.h"
#include "kona_se.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "delivery_request.h"
#include "delivery_response.h"
#include "delivery_done.h"
#include "apdu.h"
//#include "default_params.h"

#include "tsm_debug.h"
#include "comm_se_tsm.h"
//#include "esp_tls.h"
#include <esp_log.h>
//#if TLS_EN
#include <mbedtls/ssl.h>
//#else
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>


//#endif

// #include <openssl/ssl.h>
// #include <openssl/err.h>
static const char * TAG = "commsetsm";

void execute_tsm_apdus(TSM_APDU** tsm_apdu)
{
	int index = 0;
	int number_of_apdus = (*tsm_apdu)->total_apdu_count;

	unsigned char response[MAX_APDU_RESPONSE_LENGTH];
	int response_len = 0;

	(*tsm_apdu)->rpdus = (CUSTOM_STRING**)malloc(sizeof(CUSTOM_STRING*)*number_of_apdus);

	for(index = 0; index < number_of_apdus; index++)
	{
		response_len=0;
		smartcard_apdu((*tsm_apdu)->apdus[index]->str, (*tsm_apdu)->apdus[index]->length, response, &response_len);
		(*tsm_apdu)->rpdus[index] = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
		(*tsm_apdu)->rpdus[index]->str = (byte*)malloc(sizeof(byte)*response_len);
		memcpy((*tsm_apdu)->rpdus[index]->str, response, response_len);
		(*tsm_apdu)->rpdus[index]->length = response_len;

		/*printf("\n\nResponse[%d]: ", index);
		for(int i=0; i< (*tsm_apdu)->rpdus[index]->length; i++){
			printf("%02X", (*tsm_apdu)->rpdus[index]->str[i]);
		}
		printf("\n\n");*/
	}

}


int call_tsm_to_get_list_info(char* request_data, int data_len, char* base_url, char* uri){
	//connect http to get tsmConnInfo
	int option = 0;
	MemoryStruct *api_response = (MemoryStruct*)malloc(sizeof(MemoryStruct));
	char* url = buildUrl(base_url, uri);
	int status = requestHttp(request_data,data_len, url, &api_response, option);
	free(url);
	
    	if(api_response->size == 0){
        	return -1;
    	}
	Applet_List_Response_Struct* appletlist_response = NULL;
	get_applet_list_response_from_json_string(api_response->memory,&appletlist_response);
		free(api_response);
	if(appletlist_response->status == TSM_OK){
		free(appletlist_response->service_list);
		free(appletlist_response);
		Applet_List_Response_Struct* appletlist_response = NULL;
	}else{
		printf("\nError: %s\n",appletlist_response->error_msg);
		free(appletlist_response->error_msg);
		appletlist_response->error_msg = NULL;
	}

	//print_tsm_conn_info(*tsm_conn_info);
	return 0;
}

int call_tsm_to_get_status_info(char* request_data, int data_len, char* base_url, char* uri){
	//connect http to get tsmConnInfo
	int option = 0;
	MemoryStruct *api_response = (MemoryStruct*)malloc(sizeof(MemoryStruct));
	char* url = buildUrl(base_url, uri);
	int status = requestHttp(request_data,data_len, url, &api_response, option);
	free(url);
	
    	if(api_response->size == 0){
        	return -1;
    	}
	Checkse_TSM_Response_Struct* checkse_response = NULL;
	get_checkse_tsm_response_from_json_string(api_response->memory,&checkse_response);
		free(api_response);
	if(checkse_response->status == TSM_OK){
		free(checkse_response->se_list);
		free(checkse_response);
		Checkse_TSM_Response_Struct* checkse_response = NULL;
	}else{
		printf("\nError: %s\n",checkse_response->error_msg);
		free(checkse_response->error_msg);
		checkse_response->error_msg = NULL;
	}

	//print_tsm_conn_info(*tsm_conn_info);
	return 0;
}

int call_tsm_to_get_connection_info(char* request_data, int data_len, cJSON_bool is_polling, char* base_url, char* uri, TSM_Connection_Info_Struct** tsm_conn_info, char** msg_id, char** sir_id){
	//connect http to get tsmConnInfo
	int option = 0;
	if(!strcmp(uri, URI_DEVICE_DELETE_APPLET)) {
		option = 1;
	}
	MemoryStruct *api_response = (MemoryStruct*)malloc(sizeof(MemoryStruct));
	char* url = buildUrl(base_url, uri);
	int status = requestHttp(request_data,data_len, url, &api_response, option);
	free(url);
	
    	if(api_response->size == 0){
        	return -1;
    	}
	if(is_polling){
		GSM_TSM_Response_Struct* gsm_response;
		get_gsm_tsm_response_from_json_string(api_response->memory,&gsm_response);
		free(api_response);
		if(gsm_response->status == TSM_OK){
			*tsm_conn_info = gsm_response->tsm_conn_info;
			gsm_response->tsm_conn_info = NULL;
		}else{
			printf("\nError: %s\n",gsm_response->error_msg);
			free(gsm_response->error_msg);
			gsm_response->error_msg = NULL;
			return -1;
		}

		*msg_id = gsm_response->msg_id;
		gsm_response->msg_id = NULL;
		*sir_id = gsm_response->sir_id;
		gsm_response->sir_id = NULL;

		//msg_id, and tsm_conn_info will be freed later
	}else{
		Base_TSM_Response_Struct* base_response = NULL;
		get_base_tsm_response_from_json_string(api_response->memory,&base_response);
		free(api_response);
		if(base_response->status == TSM_OK){
			*tsm_conn_info = base_response->tsm_conn_info;
			base_response->tsm_conn_info = NULL;
		}else{
			printf("\nError: %s\n",base_response->error_msg);
			free(base_response->error_msg);
			base_response->error_msg = NULL;
			return -1;
		}
	}
	
	//print_tsm_conn_info(*tsm_conn_info);
	return 0;
}

int check_gsm_callback(char* msg_id,TSM_HTTP_Request_Type tsm_req_type, char* base_url){

	printf("\nChecking gsm_callback_status by calling TSM");
	MemoryStruct *api_response_data = (MemoryStruct*)malloc(sizeof(MemoryStruct));
	cJSON* request_data_json2 = cJSON_CreateObject();

	cJSON_AddStringToObject(request_data_json2, "msgId", msg_id);
	int delay = 0;
	char* gsm_request_type = NULL;
	if(tsm_req_type == REGISTER_SE){
		gsm_request_type = "registerseid";
		delay = 2;
	}else if(tsm_req_type == ISSUE_APPLET){
		gsm_request_type = "DeployService";
		delay = 11;
	}else if(tsm_req_type == DELETE_APPLET){
		gsm_request_type = "DeployService";
		delay = 11;
	}

	cJSON_AddStringToObject(request_data_json2, "gsmMsg", gsm_request_type);
	cJSON_AddBoolToObject(request_data_json2, "isLock", false);//false in every request
	char* request_data_str2 = cJSON_Print(request_data_json2);
	long data_len2 = strlen(request_data_str2);
	printf("\nRequestJSON: %s",request_data_str2);

	//delay is needed to get proper server response
	sleep(delay);

	char* url = buildUrl(base_url, URI_DEVICE_GSM_CALLBACK_RESPONSE);
	int http_status = requestHttp(request_data_str2,data_len2,url, &api_response_data, 0);
	free(url);
	if(api_response_data->size == 0){
        return -1;
	}

	cJSON* response_status = cJSON_Parse(api_response_data->memory);

	printf("\nRESPONSE: ");
	int i;
	for(i=0;i<api_response_data->size;i++){
		printf("%c",api_response_data->memory[i]);
	}

	int status = atoi(cJSON_GetStringValue(cJSON_GetObjectItem(response_status,"status")));
	free(api_response_data->memory);
	free(api_response_data);
	return status;
}

bool communicate_btwn_tsm_proxy(char* request_data_str, char* base_url, TSM_HTTP_Request_Type tsm_req_type){

	long data_len = strlen(request_data_str);
        int http_conn_success = 0;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	if(tsm_req_type == CHECK_SE)
	{
		http_conn_success = call_tsm_to_get_status_info(request_data_str, data_len, base_url, URI_DEVICE_CHECK_SE);
	}
	else if(tsm_req_type == SERVICE_LIST_ALL)
	{
		http_conn_success = call_tsm_to_get_list_info(request_data_str, data_len, base_url, URI_DEVICE_AVAILABLE_APPLETS);
	}
	else if(tsm_req_type == REGISTER_SE)
	{
		http_conn_success = call_tsm_to_get_list_info(request_data_str, data_len, base_url, URI_DEVICE_REGISTER_SEID);
	}
	else
	{
		printf("\nUnknown Request Type;ABORT");
		return false;
	}

    	if(http_conn_success<0){
        	printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        	return false;
    	}
    	return true;
}

#define RX_BUF_SZ 40000
#if TLS_EN
static struct esp_tls *tls_open(const TSM_Connection_Info_Struct *cinfo)
{
    esp_tls_cfg_t cfg = {
        // .cacert_pem_buf   = root_ca_pem_start,
        // .cacert_pem_bytes = root_ca_pem_end - root_ca_pem_start,
        .skip_common_name = false,
        .timeout_ms       = 10000,
    };

    struct esp_tls *tls = esp_tls_init();  // 구조체 안전 할당
    if (!tls) {
        ESP_LOGE(TAG, "Failed to allocate memory for esp_tls");
        return NULL;
    }

    int ret = esp_tls_conn_new_sync(cinfo->ip, strlen(cinfo->ip),
                                    atoi(cinfo->port), &cfg, tls);
    if (ret != 1) {
        ESP_LOGE(TAG, "TLS connection failed (ret=%d)", ret);
        free(tls);  // 실패 시 반드시 해제
        return NULL;
    }

    return tls;
}
#else
static int tcp_open(const TSM_Connection_Info_Struct *cinfo)
{
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(atoi(cinfo->port)),
        .sin_addr.s_addr = inet_addr(cinfo->ip)
    };

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        return -1;
    }

    int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "Socket connect failed: errno %d", errno);
        close(sock);
        return -1;
    }

    ESP_LOGI(TAG, "Connected to %.*s:%.*s", 15, cinfo->ip, 5, cinfo->port);
    return sock;
}
#endif
bool communicate_tsm_and_card(TSM_Connection_Info_Struct* tsm_conn_info, char* seId, char* msgId, char* appId, char* sirId){


	char msg_id[37] = {0};
	memcpy(msg_id,msgId,LEN_MSG_ID);
	//msg_id from gsm_callback_response is freed now
	free(msgId);

    /* 1) Delivery-Request 생성 --------------------------------------- */
    TSM_Delivery_Request *d_req = calloc(1, sizeof(TSM_Delivery_Request));
    d_req->app_id              = malloc(sizeof(CUSTOM_STRING));
    d_req->app_id->length      = 24;
    d_req->app_id->str         = malloc(24);
    memcpy(d_req->app_id->str, appId, 24);
    int conv_id_len = tsm_conn_info->conversation_id->length;
    d_req->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
    d_req->conversation_id->str = (byte*)malloc(sizeof(byte)*conv_id_len);
    memcpy(d_req->conversation_id->str,tsm_conn_info->conversation_id->str,conv_id_len);
    d_req->conversation_id->length = conv_id_len;

    d_req->delivery_idx = 1;

    if(seId == NULL){
        seId = "00";
    }
    d_req->seid = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
    int seid_len = strlen(seId);
    d_req->seid->str = (byte*)malloc(sizeof(byte)*seid_len);
    memcpy(d_req->seid->str,seId,seid_len);
    d_req->seid->length = seid_len;

    if(sirId == NULL){
        sirId = "00";
    }
    int sir_len = strlen(sirId);
    d_req->sir = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
    d_req->sir->str = (byte*)malloc(sizeof(byte)*sir_len);
    memcpy(d_req->sir->str,sirId,sir_len);
    d_req->sir->length = sir_len;

    d_req->header = (TSM_Packet_Header*)malloc(sizeof(TSM_Packet_Header));
    d_req->header->version = 1;
    d_req->header->direction = TO_TSM;
    d_req->header->msg_type = DELIVERY_REQUEST;
    d_req->header->total_count = 1;
    d_req->header->current_count = 1;
    d_req->header->k_ic = 0;
    d_req->header->k_id = 0;
    d_req->header->enc_yn = 0;
    d_req->header->conversation_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
    d_req->header->conversation_id->str = (byte*)malloc(sizeof(byte)*conv_id_len);
    memcpy(d_req->header->conversation_id->str,tsm_conn_info->conversation_id->str,conv_id_len);
    d_req->header->conversation_id->length = conv_id_len;

    int host_id_len = tsm_conn_info->host_name->length;
    d_req->header->host_id = (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
    d_req->header->host_id->str = (byte*)malloc(sizeof(byte)*host_id_len);
    memcpy(d_req->header->host_id->str,tsm_conn_info->host_name->str,host_id_len);
    d_req->header->host_id->length = host_id_len;

    char *tx_buf    = NULL;
    int   tx_len    = get_byte_array_from_tsm_delivery_request(d_req, &tx_buf);
    char *rx_buf    = malloc(RX_BUF_SZ);
    int   is_done   = 0;

    do {
		#if TLS_EN
        /* 2) TLS 연결 ------------------------------------------------- */
		struct esp_tls *tls = tls_open(tsm_conn_info);
		if (!tls) {
			ESP_LOGE(TAG, "TLS conn fail");
			break;
		}
		ESP_LOGI(TAG, "TLS connected successfully");

        /* 3) Delivery-Request 전송 ----------------------------------- */
        if (esp_tls_conn_write(tls, tx_buf, tx_len) < 0) {
            ESP_LOGE(TAG, "Write error"); esp_tls_conn_destroy(tls); break;
        }

        int rlen = esp_tls_conn_read(tls, rx_buf, RX_BUF_SZ);
        if (rlen <= 0) { ESP_LOGE(TAG, "Read error"); esp_tls_conn_destroy(tls); break; }
		#else
		        int sock = tcp_open(tsm_conn_info);
        if (sock < 0) break;

        if (send(sock, tx_buf, tx_len, 0) < 0) {
            ESP_LOGE(TAG, "Send failed");
            close(sock);
            break;
        }

        int rlen = recv(sock, rx_buf, RX_BUF_SZ, 0);
        if (rlen <= 0) {
            ESP_LOGE(TAG, "Receive failed");
            close(sock);
            break;
        }
		#endif

        /* 4) 수신 루프 ------------------------------------------------ */
        while (true) {
            TSM_Packet_Header *hdr = NULL;
            parse_tsm_header(rx_buf, &hdr);

            if (hdr->msg_type == DELIVERY_RESPONSE) {
				printf("\nmsg_type == DELIVERY_RESPONSE");
                /* 추가 read 로 전체 packet 수신 */
				int valread = recv(sock, rx_buf, RX_BUF_SZ, 0);
				int offset = valread;
				parse_tsm_header(rx_buf, &hdr);
                while (offset < hdr->body_length + HEADER_LENGTH) {
					#if TLS_EN
                    int add = esp_tls_conn_read(tls, rx_buf + rlen, RX_BUF_SZ - rlen);
					#else
					valread = recv(sock, rx_buf + offset, RX_BUF_SZ - rlen, 0);
					#endif
                    if (valread <= 0) break;
                    offset += valread;
                }
            }
            else if (hdr->msg_type == APDU_COMMAND
                  || hdr->msg_type == APDU_RESPONSE) {
				printf("\nmsg_type == APDU PACKET\n");
                TSM_APDU *apdu = NULL;
                parse_tsm_apdu(rx_buf, &apdu);
                execute_tsm_apdus(&apdu);

                apdu->header->msg_type  = APDU_RESPONSE;
                apdu->header->direction = TO_TSM;

                char *apdu_bytes = NULL;
                int   apdu_len   = get_byte_array_from_apdu(apdu, &apdu_bytes, false);
				#if TLS_EN
                esp_tls_conn_write(tls, apdu_bytes, apdu_len);
				#else
				send(sock, apdu_bytes, apdu_len, 0);
				#endif
                free(apdu_bytes);
                free_apdu(&apdu);

				#if TLS_EN
                rlen = esp_tls_conn_read(tls, rx_buf, RX_BUF_SZ);
				#else
				int valread = recv(sock, rx_buf, RX_BUF_SZ, 0);
				int offset = valread;
				parse_tsm_header(rx_buf, &hdr);
                while (offset < hdr->body_length + HEADER_LENGTH) {
					#if TLS_EN
                    int add = esp_tls_conn_read(tls, rx_buf + rlen, RX_BUF_SZ - rlen);
					#else
					valread = recv(sock, rx_buf + offset, RX_BUF_SZ - rlen, 0);
					#endif
                    if (valread <= 0) break;
                    offset += valread;
                }
				#endif
            }
            else if (hdr->msg_type == DELIVERY_DONE) {
                TSM_Delivery_Done *done = NULL;
                parse_tsm_delivery_done(rx_buf, &done);

                done->header->msg_type  = DELIVERY_DONE_ACK;
                done->header->direction = TO_TSM;

                char *ack = NULL;
                int   alen= get_byte_array_from_delivery_done(done, &ack);
				#if TLS_EN
                esp_tls_conn_write(tls, ack, alen);
				#else
				send(sock, ack, alen, 0);
				close(sock);
				#endif
                free(ack);

                is_done = 1;
                break;
            } else {
				printf("msg_type = %02X\n", hdr->msg_type);
				printf("\nmsg_type == DELEVERY_DONE_LAST\n");
				close(sock);
				break;
			}

            free_tsm_header(&hdr);
			// #if TLS_EN
            // rlen = esp_tls_conn_read(tls, rx_buf, RX_BUF_SZ);
			// #else
			// rlen = recv(sock, rx_buf, RX_BUF_SZ, 0);
			// #endif
        }
		#if TLS_EN
        esp_tls_conn_destroy(tls);
		#else
		//close(sock);
		#endif
    } while (!is_done);

    /* 5) 메모리 정리 --------------------------------------------------- */
    free_delivery_request(&d_req);
    free(tx_buf);  free(rx_buf);

    return (is_done != 0);
}

