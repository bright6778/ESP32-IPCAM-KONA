/*
 * tsm_sdk.h
 *
 *  Created on: May 11, 2024
 *      Author: yang.sg
 */

#ifndef TSM_SDK_INCLUDE_TSM_SDK_H_
#define TSM_SDK_INCLUDE_TSM_SDK_H_

#include "kona_se.h"
#include "enums.h"
#include "comm_se_tsm.h"
#include "tsm_debug.h"

#define MAX_BASE_URL_LENGTH 100
#define MAX_APP_ID_LENGTH 100

typedef struct {
    char* seId;
    SeIdType seIdType;
    SeType seType;
    bool isPolling;
    //char* seManufacturer;
    //SeStatus seStatus;
    //char* sePImageUrl;
} SeDetail;

int tsm_sdk_init();
void set_base_url(char* str);
char* get_base_url();
void set_app_id(char* str);
char* get_app_id();
bool check_se(char* imei, SeDetail seList[], int seListSize);
bool servicelistall(char* imei, char* seId, SeIdType sdIdType, SeType seType);
bool register_se(char* imei, char* cplc, SeType seType);
bool audit_se(char* imei, char* seId);
bool issue_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer, char* customerId);
bool delete_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer);
bool lockunlock_applet(char* imei, char* seId, char* aId, char* serviceId, char* serviceVer, bool is_lock);
bool register_device_info(char* imei, char* pushToken, Push_Token_Type pushType, char* osName, char* osVersion,char* msisdn, char* mnoName);



#endif /* TSM_SDK_INCLUDE_TSM_SDK_H_ */
