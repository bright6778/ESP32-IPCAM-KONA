/*
 * comm_se_in_tsm.h
 *
 *  Created on: May 4, 2024
 *      Author: sg,yang
 */

#ifndef TSM_SDK_INCLUDE_COMM_SE_IN_TSM_H_
#define TSM_SDK_INCLUDE_COMM_SE_IN_TSM_H_

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

int call_tsm_to_get_list_info(char* request_data,int data_len,char* base_url,char* uri);
int call_tsm_to_get_status_info(char* request_data,int data_len,char* base_url,char* uri);
int call_tsm_to_get_connection_info(char* request_data, int data_len, cJSON_bool is_polling, char* base_url, char* uri, TSM_Connection_Info_Struct** tsm_conn_info, char** msg_id, char** sir_id);
bool communicate_btwn_tsm_proxy(char* request_data_str, char* base_url, TSM_HTTP_Request_Type tsm_req_type);
bool communicate_tsm_and_card(TSM_Connection_Info_Struct* tsm_conn_info, char* seId, char* msgId, char* appId, char* sirId);
//bool communicate_btwn_tsm_and_card(cJSON* request_json,cJSON_bool is_polling,TSM_HTTP_Request_Type tsm_req_type);

#endif /* TSM_SDK_INCLUDE_INTERFACE_SE_IN_TSM_H_ */
