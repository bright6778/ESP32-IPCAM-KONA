/*
 * tsm_sdk.cpp
 *
 *  Created on: Apr 17, 2018
 *      Author: Autonu
 */

#include "http_requester.h"
#include "comm_se_tsm.h"
#include "response_structs.h"
#include <cJSON.h>
#include "http_conf.h"
#include "enums.h"
#include "kona_se.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
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
#include "tsm_sdk.h"

#define JSON_OBJECT_STRING_LEN 256

char base_url[MAX_BASE_URL_LENGTH] = {0};
char app_id[MAX_APP_ID_LENGTH] = {0};
//char* base_url = NULL;
//char* app_id = NULL;

int tsm_sdk_init()
{
    if(tsm_sdk_debug_init() != 0)
    {
        return -1;
    }

    return 0;
}

void set_base_url(char* str) {
	if(strlen(str) >= MAX_BASE_URL_LENGTH) {
		printf("Error: Input base_url is too long.\n");
		return;
	}
	strcpy(base_url, str);
	/*if(base_url != NULL)  {
		free(base_url);
	}
	base_url = (char *)malloc(strlen(str) + 1);
	if(base_url != NULL) {
		strcpy(base_url, str);
	}*/
}

char* get_base_url() {
	if(base_url[0] == '\0') {
		printf("Error: No base_url stored.\n");
		return NULL;
	}
	return base_url;

	/*if(base_url == NULL) {
		printf("Error: No base_url stored.\n");
		return NULL;
	}
	return base_url;*/
}


void set_app_id(char* str) {
	if(strlen(str) >= MAX_APP_ID_LENGTH) {
		printf("Error: Input app_id is too long.\n");
		return;
	}
	strcpy(app_id, str);
	/*if(app_id != NULL)  {
		free(app_id);
	}
	app_id = (char *)malloc(strlen(str) + 1);
	if(app_id != NULL) {
		strcpy(app_id, str);
	}*/
}

char* get_app_id() {
	if(app_id[0] == '\0') {
		printf("Error: No app_id stored.\n");
		return NULL;
	}
	return app_id;
	/*if(app_id == NULL) {
		printf("Error: No app_id stored.\n");
		return NULL;
	}
	return app_id;*/
}

char* se_detail_to_json(SeDetail seList[], int seListSize) {
	const char* seIdType = "00";
	const char* seType = "00";
	char* jsonArray = (char*)malloc(JSON_OBJECT_STRING_LEN * seListSize);
	if(jsonArray == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

	strcpy(jsonArray, "[");

	for(int i = 0; i < seListSize; ++i) {
		char seJson[JSON_OBJECT_STRING_LEN];
		switch (seList[i].seIdType) {
			case ICCID:
				seIdType = "01";
				break;
			case CARD_UNIQUE_DATA:
				seIdType = "02";
				break;
			default:
				fprintf(stderr, "Unknown seIdType: %d\n", seList[i].seIdType);
				seIdType = "00";
				break;
		};
		switch (seList[i].seType) {
			case SIM:
				seType = "01";
				break;
			case eSE:
				seType = "02";
				break;
			case MSD:
				seType = "03";
				break;
			case GENERAL_IC_CARD:
				seType = "04";
				break;
			case OTHER:
				seType = "05";
				break;
			default:
				break;
		};

		snprintf(seJson, JSON_OBJECT_STRING_LEN,
				"{\"seId\":\"%s\",\"seIdType\":\"%s\",\"seType\":\"%s\",\"isPolling\":%s}",
				seList[i].seId, seIdType, seType, seList[i].isPolling ? "true" : "false");
		strcat(jsonArray, seJson);

		if(i != seListSize - 1) {
			strcat(jsonArray, ",");
		}
	}

	strcat(jsonArray, "]");
	return jsonArray;
}

char* check_se_eligibility_to_json(char* imei, SeDetail seList[], int seListSize) {
	char* seJsonArray = se_detail_to_json(seList, seListSize);
	char* reqJson = (char*)malloc(JSON_OBJECT_STRING_LEN + strlen(imei) + strlen(seJsonArray));
	if(reqJson == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

	snprintf(reqJson, JSON_OBJECT_STRING_LEN + strlen(imei) + strlen(seJsonArray),
				"{\"imei\":\"%s\",\"seList\":%s}",
				imei, seJsonArray);
	free(seJsonArray);
	return reqJson;
}

bool check_se(char* imei, SeDetail seList[], int seListSize)
{

	bool ret = false;

	char* reqJson = check_se_eligibility_to_json(imei, seList, seListSize);
	ret = communicate_btwn_tsm_proxy(reqJson,base_url,CHECK_SE);
	free(reqJson);	
	return ret;

}

bool servicelistall(char* imei, char* seId, SeIdType seIdType, SeType seType)
{

	bool ret = false;
	const char* seIdType_str = "00";
	const char* seType_str = "00";
	char reqJson[JSON_OBJECT_STRING_LEN];

	switch (seIdType) {
		case ICCID:
			seIdType_str = "01";
			break;
		case CARD_UNIQUE_DATA:
			seIdType_str = "02";
			break;
		default:
			break;
	};

	switch (seType) {
		case SIM:
			seType_str = "01";
			break;
		case eSE:
			seType_str = "02";
			break;
		case MSD:
			seType_str = "03";
			break;
		case GENERAL_IC_CARD:
			seType_str = "04";
			break;
		case OTHER:
			seType_str = "05";
			break;
		default:
			break;
	};

	snprintf(reqJson, JSON_OBJECT_STRING_LEN,
				"{\"imei\":\"%s\",\"seId\":\"%s\",\"seIdType\":\"%s\",\"seType\":\"%s\"}",
				imei, seId, seIdType_str, seType_str);
	

	ret = communicate_btwn_tsm_proxy(reqJson, base_url, SERVICE_LIST_ALL);
	return ret;

}

bool register_se(char* imei, char* cplc, SeType seType)
{

	bool ret = false;

	const char* seType_str = "00";

	switch (seType) {
		case SIM:
			seType_str = "01";
			break;
		case eSE:
			seType_str = "02";
			break;
		case MSD:
			seType_str = "03";
			break;
		case GENERAL_IC_CARD:
			seType_str = "04";
			break;
		case OTHER:
			seType_str = "05";
			break;	
		default:
			break;
	};
	cJSON_bool is_polling = true;

	cJSON* request_data_json = cJSON_CreateObject();
	cJSON_AddStringToObject(request_data_json, "imei", imei);
	cJSON_AddStringToObject(request_data_json, "cplc", cplc);
	cJSON_AddStringToObject(request_data_json, "seType", seType_str);
	cJSON_AddBoolToObject(request_data_json,"isPolling",is_polling);

	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, is_polling, base_url, URI_DEVICE_REGISTER_SEID, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	ret = communicate_tsm_and_card(tsm_conn_info, NULL, parsed_msg_id, app_id, NULL);

	free_tsm_conn_info(&tsm_conn_info);
	return ret;

}

bool audit_se(char* imei, char* seId)
{

	bool ret = false;

	cJSON_bool is_polling = true;

	cJSON* request_data_json = cJSON_CreateObject();
	cJSON_AddStringToObject(request_data_json, "imei", imei);
	cJSON_AddStringToObject(request_data_json, "seId", seId);
	cJSON_AddBoolToObject(request_data_json,"isPolling",is_polling);

	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, is_polling, base_url, URI_DEVICE_SEAUDIT, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	ret = communicate_tsm_and_card(tsm_conn_info, seId, parsed_msg_id, app_id, NULL);

	free_tsm_conn_info(&tsm_conn_info);
	return ret;

}

bool issue_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer, char* customerId)
{

	bool ret = false;
	cJSON_bool is_polling = true;
	cJSON_bool is_wait_work = false;

	cJSON* request_data_json = cJSON_CreateObject();
	cJSON_AddStringToObject(request_data_json, "imei", imei);
	cJSON_AddStringToObject(request_data_json, "seId", seId);
	cJSON_AddStringToObject(request_data_json, "AID", aId);
	cJSON_AddStringToObject(request_data_json, "serviceID", serviceId);
	cJSON_AddStringToObject(request_data_json, "serviceVersion", serviceVer);
	cJSON_AddStringToObject(request_data_json, "customerID", customerId);
	cJSON_AddBoolToObject(request_data_json,"isPolling",is_polling);
	cJSON_AddBoolToObject(request_data_json, "isWaitWork", is_wait_work);

	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, is_polling, base_url, URI_DEVICE_ISSUE_APPLET, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	ret = communicate_tsm_and_card(tsm_conn_info, seId, parsed_msg_id, app_id, parsed_sir_id);

	free_tsm_conn_info(&tsm_conn_info);
	return ret;

}

bool delete_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer)
{

	bool ret = false;
	cJSON_bool is_polling = true;
	cJSON_bool is_wait_work = false;

	cJSON* request_data_json = cJSON_CreateObject();
	cJSON_AddStringToObject(request_data_json, "imei", imei);
	cJSON_AddStringToObject(request_data_json, "seId", seId);
	cJSON_AddStringToObject(request_data_json, "AID", aId);
	cJSON_AddStringToObject(request_data_json, "serviceID", serviceId);
	cJSON_AddStringToObject(request_data_json, "serviceVersion", serviceVer);
	cJSON_AddBoolToObject(request_data_json,"isPolling",is_polling);
	cJSON_AddBoolToObject(request_data_json, "isWaitWork", is_wait_work);

	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, is_polling, base_url, URI_DEVICE_DELETE_APPLET, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	ret = communicate_tsm_and_card(tsm_conn_info, seId, parsed_msg_id, app_id, parsed_sir_id);

	free_tsm_conn_info(&tsm_conn_info);
	return ret;

}

bool lockunlock_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer, bool is_lock)
{

	bool ret = false;
	cJSON_bool is_polling = true;
	cJSON_bool is_wait_work = false;

	cJSON* request_data_json = cJSON_CreateObject();
	cJSON_AddStringToObject(request_data_json, "imei", imei);
	cJSON_AddStringToObject(request_data_json, "seId", seId);
	cJSON_AddStringToObject(request_data_json, "AID", aId);
	cJSON_AddStringToObject(request_data_json, "serviceID", serviceId);
	cJSON_AddStringToObject(request_data_json, "serviceVersion", serviceVer);
	cJSON_AddBoolToObject(request_data_json, "isLock", is_lock);
	cJSON_AddBoolToObject(request_data_json,"isPolling",is_polling);
	cJSON_AddBoolToObject(request_data_json, "isWaitWork", is_wait_work);

	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, is_polling, base_url, URI_DEVICE_LOCK_UNLOCK_APPLET, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	ret = communicate_tsm_and_card(tsm_conn_info, seId, parsed_msg_id, app_id, parsed_sir_id);

	free_tsm_conn_info(&tsm_conn_info);
	return ret;

}

bool register_device_info(char* imei, char* pushToken, Push_Token_Type pushType, char* osName,char* osVersion,char* msisdn, char* mnoName)
{

	const char* pushType_str = "00";

	switch (pushType) {
		case FCM:
			pushType_str = "00";
			break;
		case Xinjie:
			pushType_str = "01";
			break;
		case NOT_MOBILE:
			pushType_str = "02";
			break;
		default:
			break;
	};
	cJSON* request_data_json = cJSON_CreateObject();

	cJSON_AddStringToObject(request_data_json, "imei", imei);
	//cJSON_AddStringToObject(request_data_json, "pushToken", pushToken);
	cJSON_AddStringToObject(request_data_json, "pushType", pushType_str);
	//cJSON_AddStringToObject(request_data_json, "osName", osName);
	//cJSON_AddStringToObject(request_data_json, "osVersion", osVersion);
	//cJSON_AddStringToObject(request_data_json, "msisdn", msisdn);
	//cJSON_AddStringToObject(request_data_json, "mnoName", mnoName);


	int http_conn_success = 0;
	char* request_data_str = cJSON_Print(request_data_json);
	long data_len = strlen(request_data_str);
	char* parsed_msg_id = NULL;
	char* parsed_sir_id = NULL;

	TSM_Connection_Info_Struct* tsm_conn_info = NULL;

	http_conn_success = call_tsm_to_get_connection_info(request_data_str, data_len, false, base_url, URI_DEVICE_REGISTER_DEVICE_INFO, &tsm_conn_info, &parsed_msg_id, &parsed_sir_id);

	if(http_conn_success<0){
        printf("\nConnection to TSM proxy failed, Operation terminated.\n");
        return false;
    }

	return true;
}
