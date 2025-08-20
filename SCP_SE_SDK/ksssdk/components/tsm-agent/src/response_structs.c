#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cJSON.h>
#include "response_structs.h"
#include "enums.h"


#define STATUS_OK 						"00"
#define STATUS_WRONG_INPUT_PARAMS 		"01"
#define STATUS_DUPLICATED_SE 			"03"
#define STATUS_INTERNAL_SERVER_ERROR 	"99"

void get_status_code_from_response(char* status, TSM_HTTP_Response_Status_code* response_status)
{
	if(strcmp(STATUS_OK, status) == 0)
	{
		*response_status = TSM_OK;
	}
	else if(strcmp(STATUS_WRONG_INPUT_PARAMS, status) == 0)
	{
		*response_status = WRONG_INPUT_PARAMS;
	}
	else if(strcmp(STATUS_DUPLICATED_SE, status) == 0)
	{
		*response_status = DUPLICATED_SE;
	}
	else if(strcmp(STATUS_INTERNAL_SERVER_ERROR, status) == 0)
	{
		*response_status = INTERNAL_SERVER_ERROR;
	}
	else
	{
		*response_status = UNKNOWN_ERROR;
	}
}

void get_sestatus_code_from_response(char* sestatus, SeLifeCycleType* response_status)
{
	if(strcmp("ACTIVATED", sestatus) == 0)
	{
		*response_status = ACTIVATED;
	}
	else if(strcmp("SUSPENDED", sestatus) == 0)
	{
		*response_status = SUSPENDED;
	}
	else if(strcmp("TERMINATED", sestatus) == 0)
	{
		*response_status = TERMINATED;
	}
	else
	{
		*response_status = 3;
	}
}

void get_se_status_info_from_json_obj(cJSON* se_status_json,SE_Status_Info_Struct** se_status_info){

	cJSON* se_id_json = cJSON_GetObjectItem(se_status_json,"seld");
	cJSON* se_statustype_json = cJSON_GetObjectItem(se_status_json,"seStatus");
	//cJSON* sep_id_json = cJSON_GetObjectItem(se_status_json,"sepId");
	//cJSON* sep_image_json = cJSON_GetObjectItem(se_status_json,"sepImage");

	SE_Status_Info_Struct* se_status_info_in_response = (SE_Status_Info_Struct*)malloc(sizeof(SE_Status_Info_Struct));

	char* se_id = cJSON_GetStringValue(se_id_json);
	se_status_info_in_response->se_id =(char*)malloc(20*sizeof(char));
	memcpy(se_status_info_in_response->se_id,se_id,strlen(se_id));
	/*char* se_id = cJSON_GetStringValue(se_id_json);
	int se_id_len = strlen(se_id);
	se_status_info_in_response->se_id = (char*)malloc(sizeof(char)*se_id_len+1);

	int i=0;
	for(i=0;i<se_id_len;i++){
		se_status_info_in_response->se_id[i] = se_id[i];
	}
	se_status_info_in_response->se_id[i] = '\0';*/

	/*if(se_statustype_json != NULL && cJSON_IsNumber(se_statustype_json)) {
		int enumValue = se_statustype_json->valueint;
		se_status_info_in_response->se_statustype = (SeLifeCycleType)enumValue;
	}*/

	char* se_statustype = cJSON_GetStringValue(se_statustype_json);
	get_sestatus_code_from_response(se_statustype, &se_status_info_in_response->se_statustype);


	/*char* sep_id = cJSON_GetStringValue(sep_id_json);
	int sep_id_len = strlen(sep_id);
	se_status_info_in_response->sep_id = (char*)malloc(sizeof(char)*sep_id_len+1);

	for(i=0;i<sep_id_len;i++){
		se_status_info_in_response->sep_id[i] = sep_id[i];
	}
	se_status_info_in_response->sep_id[i] = '\0';

	char* sep_image = cJSON_GetStringValue(sep_image_json);
	int sep_image_len = strlen(sep_image);
	se_status_info_in_response->sep_image = (char*)malloc(sizeof(char)*sep_image_len+1);

	for(i=0;i<sep_image_len;i++){
		se_status_info_in_response->sep_image[i] = sep_image[i];
	}
	se_status_info_in_response->sep_image[i] = '\0';*/

	*se_status_info = se_status_info_in_response;
}


void get_tsm_connection_info_from_json_obj(cJSON* tsm_conn_json,TSM_Connection_Info_Struct** tsm_conn_info){

	cJSON* ip_json = cJSON_GetObjectItem(tsm_conn_json,"ip");
	cJSON* port_json = cJSON_GetObjectItem(tsm_conn_json,"port");
	cJSON* host_name_json = cJSON_GetObjectItem(tsm_conn_json,"hostName");
	cJSON* conversation_id_json = cJSON_GetObjectItem(tsm_conn_json,"conversationID");//shouldn't it be conversationID??

	TSM_Connection_Info_Struct* tsm_conn_info_in_response = (TSM_Connection_Info_Struct*)malloc(sizeof(TSM_Connection_Info_Struct));

	char* ip = cJSON_GetStringValue(ip_json);
	int ip_len = strlen(ip);
	tsm_conn_info_in_response->ip = (char*)malloc(sizeof(char)*ip_len+1);

	int i=0;
	for(i=0;i<ip_len;i++){
		tsm_conn_info_in_response->ip[i] = ip[i];
	}
	tsm_conn_info_in_response->ip[i] = '\0';

	char* port = cJSON_GetStringValue(port_json);
	tsm_conn_info_in_response->port =(char*)malloc(strlen(port)*sizeof(char));
	memcpy(tsm_conn_info_in_response->port,port,strlen(port));

	char* host_name = cJSON_GetStringValue(host_name_json);
	tsm_conn_info_in_response->host_name =  (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	tsm_conn_info_in_response->host_name->str = (byte*)malloc(strlen(host_name)*sizeof(byte));
	memcpy(tsm_conn_info_in_response->host_name->str,host_name,strlen(host_name));
	tsm_conn_info_in_response->host_name->length = strlen(host_name);

	char* conversation_id = cJSON_GetStringValue(conversation_id_json);
	tsm_conn_info_in_response->conversation_id =  (CUSTOM_STRING*)malloc(sizeof(CUSTOM_STRING));
	tsm_conn_info_in_response->conversation_id->str = (byte*)malloc(strlen(conversation_id)*sizeof(byte));
	memcpy(tsm_conn_info_in_response->conversation_id->str,conversation_id,strlen(conversation_id));
	tsm_conn_info_in_response->conversation_id->length = strlen(conversation_id);

	*tsm_conn_info = tsm_conn_info_in_response;
}


void get_gsm_tsm_response_from_json_string(char* response_json, GSM_TSM_Response_Struct** gsm_response){
	printf("\nIn method to parse gsm_tsm_response json\n");

	cJSON* gsm_response_json_obj = cJSON_Parse(response_json);

	GSM_TSM_Response_Struct *gsm_response_from_tsm = (GSM_TSM_Response_Struct*)malloc(sizeof(GSM_TSM_Response_Struct));

	cJSON* status_json = cJSON_GetObjectItem(gsm_response_json_obj,"status");

	char* status = cJSON_GetStringValue(status_json);

	get_status_code_from_response(status,&gsm_response_from_tsm->status);

	if(cJSON_HasObjectItem(gsm_response_json_obj,"msgId")){

		cJSON* msg_id_json = cJSON_GetObjectItem(gsm_response_json_obj,"msgId");

		char* msg_id = cJSON_GetStringValue(msg_id_json);
		gsm_response_from_tsm->msg_id =(char*)malloc(strlen(msg_id)*sizeof(char)+1);
		memcpy(gsm_response_from_tsm->msg_id,msg_id,strlen(msg_id));
		msg_id[strlen(msg_id)] = '\0';
	}else{
		gsm_response_from_tsm->msg_id = NULL;
	}

	if(cJSON_HasObjectItem(gsm_response_json_obj,"SIRId")){

		cJSON* sir_id_json = cJSON_GetObjectItem(gsm_response_json_obj,"SIRId");

		char* sir_id = cJSON_GetStringValue(sir_id_json);
		gsm_response_from_tsm->sir_id =(char*)malloc(strlen(sir_id)*sizeof(char)+1);
		memcpy(gsm_response_from_tsm->sir_id,sir_id,strlen(sir_id));
		sir_id[strlen(sir_id)] = '\0';
	}else{
		gsm_response_from_tsm->sir_id = NULL;
	}

	if(cJSON_HasObjectItem(gsm_response_json_obj,"erroMsg")){

		cJSON* error_msg_json = cJSON_GetObjectItem(gsm_response_json_obj,"erroMsg");//shouldn't it be errorMsg??

		char* error_msg = cJSON_GetStringValue(error_msg_json);
		gsm_response_from_tsm->error_msg =(char*)malloc(strlen(error_msg)*sizeof(char)+1);
		memcpy(gsm_response_from_tsm->error_msg,error_msg,strlen(error_msg));
		error_msg[strlen(error_msg)] = '\0';
	}else{
		gsm_response_from_tsm->error_msg = NULL;
	}

	if(cJSON_HasObjectItem(gsm_response_json_obj,"tsmconnInfo")){

		cJSON* tsm_conn_info_json = cJSON_GetObjectItem(gsm_response_json_obj,"tsmconnInfo");
		//gsm_response_from_tsm->tsm_conn_info = (TSM_Connection_Info_Struct*)malloc(sizeof(TSM_Connection_Info_Struct));
			
		get_tsm_connection_info_from_json_obj(tsm_conn_info_json,&gsm_response_from_tsm->tsm_conn_info);
	}else{
		gsm_response_from_tsm->tsm_conn_info = NULL;
	}

	*gsm_response = gsm_response_from_tsm;
}

// void get_applet_list_response_from_json_string(char* response_json,Applet_List_Response_Struct** appletlist_response){

// 	printf("\nIn method to parse applet_list_response json\n");

// 	cJSON* appletlist_response_json_obj = cJSON_Parse(response_json);

// 	Applet_List_Response_Struct *appletlist_response_from_tsm = ( Applet_List_Response_Struct*)malloc(sizeof( Applet_List_Response_Struct));

// 	cJSON* status_json = cJSON_GetObjectItem(appletlist_response_json_obj,"status");

// 	char* status = cJSON_GetStringValue(status_json);
// 	get_status_code_from_response(status,&appletlist_response_from_tsm->status);

// 	if(cJSON_HasObjectItem(appletlist_response_json_obj,"erroMsg")){

// 		cJSON* error_msg_json = cJSON_GetObjectItem(appletlist_response_json_obj,"erroMsg");//shouldn't it be errorMsg??

// 		char* error_msg = cJSON_GetStringValue(error_msg_json);
// 		appletlist_response_from_tsm->error_msg =(char*)malloc(strlen(error_msg)*sizeof(char)+1);
// 		memcpy(appletlist_response_from_tsm->error_msg,error_msg,strlen(error_msg));
// 		error_msg[strlen(error_msg)] = '\0';
// 	}else{
// 		appletlist_response_from_tsm->error_msg = NULL;
// 	}

// 	cJSON* applet_list_info_json = cJSON_GetObjectItem(appletlist_response_json_obj,"serviceList");
// 	if(applet_list_info_json != NULL && cJSON_IsArray(applet_list_info_json)) {
// 		int array_size = cJSON_GetArraySize(applet_list_info_json);
// 		appletlist_response_from_tsm->service_list = (Service_List_Info_Struct *)malloc(array_size * sizeof(Service_List_Info_Struct));
// 		//Service_List_Info_Struct * service_list = (Service_List_Info_Struct *)malloc(array_size * sizeof(Service_List_Info_Struct));
// 		cJSON *serviceListItem = NULL;
// 		int index = 0;
// 		cJSON_ArrayForEach(serviceListItem, applet_list_info_json) {
// 			cJSON *svcIdItem = cJSON_GetObjectItem(serviceListItem, "svcId");
// 			cJSON *svcVerItem = cJSON_GetObjectItem(serviceListItem, "svcVer");
// 			cJSON *svcNameItem = cJSON_GetObjectItem(serviceListItem, "svcName");
// 			cJSON *aidItem = cJSON_GetObjectItem(serviceListItem, "aid");
// 			cJSON *svcInsStatusItem = cJSON_GetObjectItem(serviceListItem, "svcInsStatus");
// 			cJSON *svcImgUriItem = cJSON_GetObjectItem(serviceListItem, "svcImgUri");
// 			cJSON *svcThumbnailImgUriItem = cJSON_GetObjectItem(serviceListItem, "svcThumbnailImgUri");
// 			cJSON *servicestatusItem = cJSON_GetObjectItem(serviceListItem, "servicestatus");

// 			if(svcIdItem != NULL && cJSON_IsString(svcIdItem) && svcVerItem != NULL && cJSON_IsString(svcVerItem)) {
// 				char* svcIdItem_str = cJSON_GetStringValue(svcIdItem);
// 				appletlist_response_from_tsm->service_list[index].svc_id =(char*)malloc(strlen(svcIdItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_id,svcIdItem_str,strlen(svcIdItem_str));
// 				char* svcVerItem_str = cJSON_GetStringValue(svcVerItem);
// 				appletlist_response_from_tsm->service_list[index].svc_ver =(char*)malloc(strlen(svcVerItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_ver,svcVerItem_str,strlen(svcVerItem_str));
// 				char* svcNameItem_str = cJSON_GetStringValue(svcNameItem);
// 				appletlist_response_from_tsm->service_list[index].svc_name =(char*)malloc(strlen(svcNameItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_name,svcNameItem_str,strlen(svcNameItem_str));
// 				char* aidItem_str = cJSON_GetStringValue(aidItem);
// 				appletlist_response_from_tsm->service_list[index].aid =(char*)malloc(strlen(aidItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].aid,aidItem_str,strlen(aidItem_str));
// 				char* svcInsStatusItem_str = cJSON_GetStringValue(svcInsStatusItem);
// 				appletlist_response_from_tsm->service_list[index].svc_ins_status =(char*)malloc(strlen(svcInsStatusItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_ins_status,svcInsStatusItem_str,strlen(svcInsStatusItem_str));
// 				char* svcImgUriItem_str = cJSON_GetStringValue(svcImgUriItem);
// 				appletlist_response_from_tsm->service_list[index].svc_img_uri =(char*)malloc(strlen(svcImgUriItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_img_uri,svcImgUriItem_str,strlen(svcImgUriItem_str));
// 				char* svcThumbnailImgUriItem_str = cJSON_GetStringValue(svcThumbnailImgUriItem);
// 				appletlist_response_from_tsm->service_list[index].svc_thumbnail_img_uri =(char*)malloc(strlen(svcThumbnailImgUriItem_str)*sizeof(char));
// 				memcpy(appletlist_response_from_tsm->service_list[index].svc_thumbnail_img_uri,svcIdItem_str,strlen(svcThumbnailImgUriItem_str));
// 				//char* servicestatusItem_str = cJSON_GetStringValue(servicestatusItem);
// 				//appletlist_response_from_tsm->service_list[index].servicestatus =(char*)malloc(strlen(servicestatusItem_str)*sizeof(char));
// 				//memcpy(appletlist_response_from_tsm->service_list[index].servicestatus,servicestatusItem_str,strlen(servicestatusItem_str));
// 				//strcpy(service_list[index].svc_id, svcIdItem->valuestring);
// 				/*strcpy(appletlist_response_from_tsm->service_list[index].svc_ver, svcVerItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].svc_name, svcNameItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].aid, aidItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].svc_ins_status, svcInsStatusItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].svc_img_uri, svcImgUriItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].svc_thumbnail_img_uri, svcThumbnailImgUriItem->valuestring);
// 				strcpy(appletlist_response_from_tsm->service_list[index].servicestatus, servicestatusItem->valuestring);*/
// 				index++;
// 				printf("SvcId: %s, SvcVer: %s, SvcName: %s, aid: %s, SvcInsStatus: %s, SvcImgUri: %s, SvcThumbnailImgUri: %s, ServiceStatus: %s\n", svcIdItem->valuestring, svcVerItem->valuestring, svcNameItem->valuestring, aidItem->valuestring, svcInsStatusItem->valuestring, svcImgUriItem->valuestring, svcThumbnailImgUriItem->valuestring, servicestatusItem->valuestring);
// 			}
// 		}
// 	}else{
// 		appletlist_response_from_tsm->service_list = NULL;
// 	}
// 	/*if(cJSON_HasObjectItem(checkse_response_json_obj,"seList")){

// 		cJSON* se_status_info_json = cJSON_GetObjectItem(checkse_response_json_obj,"seList");
// 		//get_tsm_connection_info_from_json_obj(tsm_conn_info_json,&sestatus_response_from_tsm->tsm_conn_info);
// 		get_se_status_info_from_json_obj(se_status_info_json,&checkse_response_from_tsm->se_list);
// 	}else{
// 		checkse_response_from_tsm->se_list = NULL;
// 	}*/

// 	*appletlist_response = appletlist_response_from_tsm;
// }
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static const char* safe_str(const char* s) { return s ? s : "(null)"; }

void get_applet_list_response_from_json_string(char* response_json,
                                               Applet_List_Response_Struct** appletlist_response)
{
    if (!response_json || !appletlist_response) {
        return;
    }
    printf("\nIn method to parse applet_list_response json\n");
	printf("\n[%s] HTTP raw response_json", (const char*)response_json);

    // 0) JSON 파싱 (널 종료 보장 안 되면 ParseWithLength를 고려)
    cJSON* root = cJSON_Parse(response_json);
    if (!root) {
        printf("JSON parse failed at: %s\n", cJSON_GetErrorPtr());
        *appletlist_response = NULL;
        return;
    }

    Applet_List_Response_Struct *out = (Applet_List_Response_Struct*)calloc(1, sizeof(*out));
    if (!out) { cJSON_Delete(root); *appletlist_response = NULL; return; }

    // 1) status
    {
        cJSON* status_json = cJSON_GetObjectItemCaseSensitive(root, "status");
        const char* status = cJSON_IsString(status_json) ? status_json->valuestring : NULL;
        if (status) {
            get_status_code_from_response(status, &out->status);
        } else {
            // 기본값/에러 처리
			
            get_status_code_from_response("UNKNOWN", &out->status);
        }
    }

    // 2) errorMsg (오타 방어)
    {
        cJSON* err_json = cJSON_GetObjectItemCaseSensitive(root, "errorMsg");
        if (!err_json) err_json = cJSON_GetObjectItemCaseSensitive(root, "erroMsg");
        if (cJSON_IsString(err_json) && err_json->valuestring) {
            out->error_msg = xstrdup(err_json->valuestring);
        } else {
            out->error_msg = NULL;
        }
    }

    // 3) serviceList
    out->service_list = NULL;
   // out->service_count = 0; // 구조체에 count 필드 추가 권장

    cJSON* arr = cJSON_GetObjectItemCaseSensitive(root, "serviceList");
    if (cJSON_IsArray(arr)) {
        int n = cJSON_GetArraySize(arr);
        if (n > 0) {
            out->service_list = (Service_List_Info_Struct*)calloc(n, sizeof(Service_List_Info_Struct));
            if (!out->service_list) { cJSON_Delete(root); /* 누수 정리 생략 */ *appletlist_response = out; return; }
      //      out->service_count = n;

            int idx = 0;
            cJSON* it = NULL;
            cJSON_ArrayForEach(it, arr) {
                Service_List_Info_Struct* svc = &out->service_list[idx];

                cJSON* svcId   = cJSON_GetObjectItemCaseSensitive(it, "svcId");
                cJSON* svcVer  = cJSON_GetObjectItemCaseSensitive(it, "svcVer");
                cJSON* svcName = cJSON_GetObjectItemCaseSensitive(it, "svcName");
                cJSON* aid     = cJSON_GetObjectItemCaseSensitive(it, "aid");
                cJSON* insSt   = cJSON_GetObjectItemCaseSensitive(it, "svcInsStatus");
                cJSON* imgUri  = cJSON_GetObjectItemCaseSensitive(it, "svcImgUri");
                cJSON* thUri   = cJSON_GetObjectItemCaseSensitive(it, "svcThumbnailImgUri");
                cJSON* stItem  = cJSON_GetObjectItemCaseSensitive(it, "servicestatus");

                const char* svcId_s   = cJSON_IsString(svcId)   ? svcId->valuestring   : NULL;
                const char* svcVer_s  = cJSON_IsString(svcVer)  ? svcVer->valuestring  : NULL;
                const char* svcName_s = cJSON_IsString(svcName) ? svcName->valuestring : NULL;
                const char* aid_s     = cJSON_IsString(aid)     ? aid->valuestring     : NULL;
                const char* insSt_s   = cJSON_IsString(insSt)   ? insSt->valuestring   : NULL;
                const char* imgUri_s  = cJSON_IsString(imgUri)  ? imgUri->valuestring  : NULL;
                const char* thUri_s   = cJSON_IsString(thUri)   ? thUri->valuestring   : NULL;
                const char* st_s      = cJSON_IsString(stItem)  ? stItem->valuestring  : NULL;

                // strdup로 안전 복사(+널)
                svc->svc_id               = xstrdup(svcId_s);
                svc->svc_ver              = xstrdup(svcVer_s);
                svc->svc_name             = xstrdup(svcName_s);
                svc->aid                  = xstrdup(aid_s);
                svc->svc_ins_status       = xstrdup(insSt_s);
                svc->svc_img_uri          = xstrdup(imgUri_s);
                svc->svc_thumbnail_img_uri= xstrdup(thUri_s);
                svc->servicestatus        = xstrdup(st_s);

                printf("SvcId:%s, SvcVer:%s, SvcName:%s, aid:%s, SvcInsStatus:%s, SvcImgUri:%s, SvcThumbnailImgUri:%s, ServiceStatus:%s\n",
                       safe_str(svcId_s), safe_str(svcVer_s), safe_str(svcName_s), safe_str(aid_s),
                       safe_str(insSt_s), safe_str(imgUri_s), safe_str(thUri_s), safe_str(st_s));

                idx++;
                if (idx >= n) break; // 방어
            }
        }
    }

    // 4) 반환
    *appletlist_response = out;

    // 5) cJSON 정리
    cJSON_Delete(root);
}

void get_checkse_tsm_response_from_json_string(char* response_json,Checkse_TSM_Response_Struct** checkse_response){

	printf("\nIn method to parse checkse_tsm_response json\n");

	cJSON* checkse_response_json_obj = cJSON_Parse(response_json);

	Checkse_TSM_Response_Struct *checkse_response_from_tsm = ( Checkse_TSM_Response_Struct*)malloc(sizeof( Checkse_TSM_Response_Struct));

	cJSON* status_json = cJSON_GetObjectItem(checkse_response_json_obj,"status");

	char* status = cJSON_GetStringValue(status_json);
	get_status_code_from_response(status,&checkse_response_from_tsm->status);

	if(cJSON_HasObjectItem(checkse_response_json_obj,"erroMsg")){

		cJSON* error_msg_json = cJSON_GetObjectItem(checkse_response_json_obj,"erroMsg");//shouldn't it be errorMsg??

		char* error_msg = cJSON_GetStringValue(error_msg_json);
		checkse_response_from_tsm->error_msg =(char*)malloc(strlen(error_msg)*sizeof(char)+1);
		memcpy(checkse_response_from_tsm->error_msg,error_msg,strlen(error_msg));
		error_msg[strlen(error_msg)] = '\0';
	}else{
		checkse_response_from_tsm->error_msg = NULL;
	}

	cJSON* se_status_info_json = cJSON_GetObjectItem(checkse_response_json_obj,"seList");
	if(se_status_info_json != NULL && cJSON_IsArray(se_status_info_json)) {
		int array_size = cJSON_GetArraySize(se_status_info_json);
		checkse_response_from_tsm->se_list = (SE_Status_Info_Struct *)malloc(array_size * sizeof(SE_Status_Info_Struct));
		cJSON *seListItem = NULL;
		int index = 0;
		cJSON_ArrayForEach(seListItem, se_status_info_json) {
			cJSON *seIdItem = cJSON_GetObjectItem(seListItem, "seId");
			cJSON *seStatusItem = cJSON_GetObjectItem(seListItem, "seStatus");
			if(seIdItem != NULL && cJSON_IsString(seIdItem) && seStatusItem != NULL && cJSON_IsString(seStatusItem)) {
				char* seIdItem_str = cJSON_GetStringValue(seIdItem);
				checkse_response_from_tsm->se_list[index].se_id =(char*)malloc(strlen(seIdItem_str)*sizeof(char));
				memcpy(checkse_response_from_tsm->se_list[index].se_id, seIdItem_str,strlen(seIdItem_str));
//				strcpy(checkse_response_from_tsm->se_list[index].se_id, seIdItem->valuestring);

				char* seStatusItem_str = cJSON_GetStringValue(seStatusItem);
				//checkse_response_from_tsm->se_list[index].se_statustype = malloc(sizeof(char));
				get_sestatus_code_from_response(seStatusItem->valuestring, &checkse_response_from_tsm->se_list[index].se_statustype);
//				strcpy(checkse_response_from_tsm->se_list[index].se_statustype, seStatusItem->valuestring);
				index++;

				printf("SeId: %s, SeStatus: %s\n", seIdItem->valuestring, seStatusItem->valuestring);
			}
		}
	}else{
		checkse_response_from_tsm->se_list = NULL;
	}
	/*cJSON* se_status_info_json = cJSON_GetObjectItem(checkse_response_json_obj,"seList");
	if(se_status_info_json != NULL && cJSON_IsArray(se_status_info_json)) {
		cJSON *seListItem;
		cJSON_ArrayForEach(seListItem, se_status_info_json) {
			cJSON *seIdItem = cJSON_GetObjectItem(seListItem, "seId");
			cJSON *seStatusItem = cJSON_GetObjectItem(seListItem, "seStatus");
			if(seIdItem != NULL && cJSON_IsString(seIdItem) && seStatusItem != NULL && cJSON_IsString(seStatusItem)) {

				printf("SeId: %s, SeStatus: %s\n", seIdItem->valuestring, seStatusItem->valuestring);
			}
		}
	}else{
		checkse_response_from_tsm->se_list = NULL;
	}*/
	/*if(cJSON_HasObjectItem(checkse_response_json_obj,"seList")){

		cJSON* se_status_info_json = cJSON_GetObjectItem(checkse_response_json_obj,"seList");
		//get_tsm_connection_info_from_json_obj(tsm_conn_info_json,&sestatus_response_from_tsm->tsm_conn_info);
		get_se_status_info_from_json_obj(se_status_info_json,&checkse_response_from_tsm->se_list);
	}else{
		checkse_response_from_tsm->se_list = NULL;
	}*/

	*checkse_response = checkse_response_from_tsm;
}

void get_base_tsm_response_from_json_string(char* response_json,Base_TSM_Response_Struct** base_response){

	printf("\nIn method to parse base_tsm_response json\n");

	printf("\n HTTP raw response_json: [%s]\n", (const char*)response_json);

	cJSON* base_response_json_obj = cJSON_Parse(response_json);

	Base_TSM_Response_Struct *base_response_from_tsm = ( Base_TSM_Response_Struct*)malloc(sizeof( Base_TSM_Response_Struct));

	cJSON* status_json = cJSON_GetObjectItem(base_response_json_obj,"status");

	char* status = cJSON_GetStringValue(status_json);
	get_status_code_from_response(status,&base_response_from_tsm->status);
	printf("\nDevice status: %s \n", status);

	if(cJSON_HasObjectItem(base_response_json_obj,"erroMsg")){

		cJSON* error_msg_json = cJSON_GetObjectItem(base_response_json_obj,"erroMsg");//shouldn't it be errorMsg??

		char* error_msg = cJSON_GetStringValue(error_msg_json);
		base_response_from_tsm->error_msg =(char*)malloc(strlen(error_msg)*sizeof(char)+1);
		memcpy(base_response_from_tsm->error_msg,error_msg,strlen(error_msg));
		error_msg[strlen(error_msg)] = '\0';
	}else{
		base_response_from_tsm->error_msg = NULL;
	}

	if(cJSON_HasObjectItem(base_response_json_obj,"tsmconnInfo")){

		cJSON* tsm_conn_info_json = cJSON_GetObjectItem(base_response_json_obj,"tsmconnInfo");
		get_tsm_connection_info_from_json_obj(tsm_conn_info_json,&base_response_from_tsm->tsm_conn_info);
	}else{
		base_response_from_tsm->tsm_conn_info = NULL;
	}

	*base_response = base_response_from_tsm;
}

void free_tsm_conn_info(TSM_Connection_Info_Struct** connection_info){

	free((*connection_info)->conversation_id->str);
	free((*connection_info)->conversation_id);
	free((*connection_info)->host_name->str);
	free((*connection_info)->host_name);
	free((*connection_info)->ip);
	free((*connection_info)->port);
	free((*connection_info));
	(*connection_info) = NULL;
}

void print_tsm_conn_info(TSM_Connection_Info_Struct* connection_info){
	printf("\nPrinting Connection Info from TSM...\n");
	int i=0;
	printf("\nConversation Id: ");
	for(i=0;i<connection_info->conversation_id->length;i++)
		printf("%c",connection_info->conversation_id->str[i]);

	printf("\nHost Name: ");
	for(i=0;i<connection_info->host_name->length;i++)
		printf("%c",connection_info->host_name->str[i]);

	printf("\nIp: %s\n",connection_info->ip);
	printf("\nPort: %s\n",connection_info->port);
}
