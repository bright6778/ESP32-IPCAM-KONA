/*
 * http_conf.h
 *
 *  Created on: Apr 13, 2018
 *      Author: Autonu
 */

#ifndef HTTP_CONF_H_
#define HTTP_CONF_H_

//#include "default_params.h"

// #define TAG "HttpTsmProxy"

#define DEFAULT_CONNECTION_TIMEOUT 30*1000
#define DEFAULT_SO_TIMEOUT 30*1000

#define  URI_DEVICE_REGISTER_DEVICE_INFO 		"/device/registerdeviceinfo"
#define  URI_DEVICE_CHECK_SE				 	"/device/checkse"
#define  URI_DEVICE_REGISTER_SEID 				"/device/registerseid"
#define  URI_DEVICE_SEAUDIT 					"/device/seaudit"
#define  URI_DEVICE_APPLET_LIFECYCLE 			"/device/appletlifecycle"
#define  URI_DEVICE_ISSUE_APPLET 				"/device/issueapplet"
#define  URI_DEVICE_LOCK_UNLOCK_APPLET  		"/device/lockunlockapplet"
#define  URI_DEVICE_DELETE_APPLET  				"/device/deleteapplet"
#define  URI_DEVICE_UPDATE_APPLET  				"/device/exchangeservicedata"
#define  URI_DEVICE_GSM_REQUEST_CHECK  			"/device/gsmrequestcheck"
#define  URI_DEVICE_SEAUDIT_SYNC  				"/device/seauditsync"
#define  URI_DEVICE_CURRENT_APPLETS  			"/device/servicelistperso"
#define  URI_DEVICE_AVAILABLE_APPLETS  			"/device/servicelistall"
#define  URI_DEVICE_GSM_CALLBACK_RESPONSE  		"/device/gsmcallbackresponse"
#define  URI_DEVICE_REGISTER_SEID_CALLBACK  	"/device/callbackregisterseid"
#define  URI_DEVICE_CHECK_WAITWORK  			"/device/checkwaitingwork"

#endif /* HTTP_CONF_H_ */
