/*
 * enums.h
 *
 *  Created on: Apr 13, 2018
 *      Author: Autonu
 */

#ifndef TSM_SDK_TSMPROXY_ENUMS_H_
#define TSM_SDK_TSMPROXY_ENUMS_H_

typedef enum _SeLifeCycleType { 
    ACTIVATED, 
    SUSPENDED, 
    TERMINATED
}SeLifeCycleType;

typedef enum {
    ACTIVE,
    NOTAVAILABLE,
    NOTREGISTERED,
    NONE1
} SeStatus;

typedef enum {
    SIM = 1,
    eSE = 3,
    MSD = 2,
    GENERAL_IC_CARD = 4,
	OTHER = 5
} SeType;

typedef enum {
    ICCID = 1,
    CARD_UNIQUE_DATA,
} SeIdType;

typedef enum _Push_Token_Type
{
	FCM,
	Xinjie,
	NOT_MOBILE
}Push_Token_Type;

typedef enum _TSM_HTTP_Response_Status_code{
	TSM_OK,
	WRONG_INPUT_PARAMS,
	DUPLICATED_SE,
	INTERNAL_SERVER_ERROR,
	UNKNOWN_ERROR
}TSM_HTTP_Response_Status_code;

typedef enum _TSM_HTTP_Request_Type{
	REGISTER_SE,
	REGISTER_DEVICE_INFO,
	ISSUE_APPLET,
	AUDIT_SE,
	DELETE_APPLET,
	LOCKUNLOCK_APPLET,
	CHECK_SE,
	SERVICE_LIST_ALL
}TSM_HTTP_Request_Type;


#endif /* TSM_SDK_TSMPROXY_ENUMS_H_ */
