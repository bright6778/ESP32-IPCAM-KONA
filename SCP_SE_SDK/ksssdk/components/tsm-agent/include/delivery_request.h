/*
 * delivery_request.h
 *
 *  Created on: May 10, 2018
 *      Author: Swasti
 */

#ifndef TSM_SDK_INCLUDE_DELIVERY_REQUEST_H_
#define TSM_SDK_INCLUDE_DELIVERY_REQUEST_H_

#include "tsm_header.h"
#include "tsm_debug.h"
#define LEN_OPCODE				  1
#define LEN_DELIVERY_IDX		  2
#define LEN_SIR				 	 60
#define LEN_SEID				 30
#define LEN_APPID				 30
#define BODY_LENGTH_DELIVERY_REQUEST LEN_CONVERSATION_ID + LEN_OPCODE + LEN_DELIVERY_IDX +LEN_SIR + LEN_SEID + LEN_APPID


typedef struct _TSM_Delivery_Request{
	CUSTOM_STRING* conversation_id;
	//	private Operation opCode;
	u_int16_t delivery_idx;
	CUSTOM_STRING* sir;
	CUSTOM_STRING* seid;
	CUSTOM_STRING* app_id;

	TSM_Packet_Header* header;

}TSM_Delivery_Request;

int get_byte_array_from_tsm_delivery_request(TSM_Delivery_Request* delivery_request, char** delivery_request_bytes);
void parse_delivery_request_packet(char* buffer,TSM_Delivery_Request** delivery_request);
void print_delivery_request(TSM_Delivery_Request* delivery_request);
void free_delivery_request(TSM_Delivery_Request** delivery_request);
#endif /* TSM_SDK_INCLUDE_DELIVERY_REQUEST_H_ */
