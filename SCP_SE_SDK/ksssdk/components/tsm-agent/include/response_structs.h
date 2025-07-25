#include "enums.h"

#include "basic_structures.h"
#include <cJSON.h>
#ifndef RESPONSE_STRUCTS_
#define RESPONSE_STRUCTS_

typedef struct _TSM_Connection_Info_Struct
{
	char* ip;
	char* port;
	CUSTOM_STRING* host_name;
	CUSTOM_STRING* conversation_id;
}TSM_Connection_Info_Struct;

typedef struct _GSM_TSM_Response_Struct
{
	TSM_HTTP_Response_Status_code status;
	char* msg_id;
	char* sir_id;
	char* error_msg;

	TSM_Connection_Info_Struct* tsm_conn_info;
}GSM_TSM_Response_Struct;

typedef struct _Service_List_Info_Struct
{
	char* svc_id;
	char* svc_ver;
	char* svc_name;
	char* aid;
	char* svc_ins_status;
	char* svc_img_uri;
	char* svc_thumbnail_img_uri;
	char* servicestatus;
}Service_List_Info_Struct;;

typedef struct _Applet_List_Response_Struct
{
	TSM_HTTP_Response_Status_code status;
	char* error_msg;
	Service_List_Info_Struct* service_list;
}Applet_List_Response_Struct;

/*enum SeLifeCycleType {
	ACTIVATED,
	SUSPENDED,
	TERMINATED,
	NONE
};*/

typedef struct _SE_Status_Info_Struct
{
	char* se_id;
	SeLifeCycleType se_statustype;
	//char* sep_id;
	//char* sep_image;
}SE_Status_Info_Struct;;

typedef struct _Check_SE_Response_Struct
{
	TSM_HTTP_Response_Status_code status;
	char* error_msg;
	SE_Status_Info_Struct* se_list;
}Checkse_TSM_Response_Struct;


typedef struct _Base_TSM_Response_Struct
{
	TSM_HTTP_Response_Status_code status;
	char* error_msg;

	TSM_Connection_Info_Struct* tsm_conn_info;
}Base_TSM_Response_Struct;

void get_gsm_tsm_response_from_json_string(char* response_json, GSM_TSM_Response_Struct** gsm_response);
void get_base_tsm_response_from_json_string(char* response_json, Base_TSM_Response_Struct** base_response);
void get_checkse_tsm_response_from_json_string(char* response_json, Checkse_TSM_Response_Struct** checkse_response);
void get_applet_list_response_from_json_string(char* response_json, Applet_List_Response_Struct** appletlist_response);
void print_tsm_conn_info(TSM_Connection_Info_Struct* connection_info);
void free_tsm_conn_info(TSM_Connection_Info_Struct** connection_info);
#endif

